use overlord_kad_proto::{KBASE, KK, NodeId};

use crate::bin::RoutingBin;
use crate::contact::Contact;
use crate::error::RoutingError;

// ── ZoneContent ───────────────────────────────────────────────────────────────

enum ZoneContent {
    Leaf(RoutingBin),
    Branch {
        /// Owns nodes where bit[depth] == 0
        left: Box<RoutingZone>,
        /// Owns nodes where bit[depth] == 1
        right: Box<RoutingZone>,
    },
}

// ── RoutingZone ───────────────────────────────────────────────────────────────

pub struct RoutingZone {
    depth: u32,
    zone_index: usize,
    content: ZoneContent,
}

impl RoutingZone {
    /// Create a new root zone.
    pub fn new_root() -> Self {
        RoutingZone {
            depth: 0,
            zone_index: 0,
            content: ZoneContent::Leaf(RoutingBin::new()),
        }
    }

    fn new_leaf(depth: u32, zone_index: usize) -> Self {
        RoutingZone {
            depth,
            zone_index,
            content: ZoneContent::Leaf(RoutingBin::new()),
        }
    }

    /// Try to add a contact.
    ///
    /// - `total_contacts`: current total in the whole table
    /// - `max_table_size`: configured maximum
    ///
    /// Returns `Ok(true)` = added new, `Ok(false)` = updated existing, `Err` = rejected.
    pub fn add(
        &mut self,
        contact: Contact,
        total_contacts: usize,
        max_table_size: usize,
    ) -> Result<bool, RoutingError> {
        match &mut self.content {
            ZoneContent::Leaf(_) => {
                // Try adding to the leaf bin.
                let result = {
                    let ZoneContent::Leaf(bin) = &mut self.content else {
                        unreachable!()
                    };
                    bin.try_add(contact.clone())
                };

                match result {
                    Ok(added) => Ok(added),
                    Err(RoutingError::TableFull { .. }) => {
                        // Attempt to split.
                        if self.can_split(total_contacts, max_table_size) {
                            self.split();
                            // Retry after split.
                            self.add(contact, total_contacts, max_table_size)
                        } else {
                            Err(RoutingError::TableFull {
                                max: max_table_size,
                            })
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            ZoneContent::Branch { left, right } => {
                let bit = contact.id.bit(self.depth);
                if bit {
                    // contact goes right
                    right.add(contact, total_contacts, max_table_size)
                } else {
                    // contact goes left
                    left.add(contact, total_contacts, max_table_size)
                }
            }
        }
    }

    /// Collect up to `n` contacts closest to `target` by XOR distance.
    ///
    /// For simplicity: recurse into all leaf bins, add contacts to result.
    /// The caller (RoutingTable) sorts by XOR distance.
    pub fn get_closest(&self, target: &NodeId, n: usize, result: &mut Vec<Contact>) {
        match &self.content {
            ZoneContent::Leaf(bin) => {
                for c in bin.iter() {
                    result.push(c.clone());
                }
            }
            ZoneContent::Branch { left, right } => {
                // Recurse into the side closer to target first (optimization, but correctness
                // doesn't depend on order since we collect all and sort).
                let bit = target.bit(self.depth);
                if bit {
                    right.get_closest(target, n, result);
                    if result.len() < n {
                        left.get_closest(target, n, result);
                    }
                } else {
                    left.get_closest(target, n, result);
                    if result.len() < n {
                        right.get_closest(target, n, result);
                    }
                }
            }
        }
    }

    /// Remove a contact by ID. Returns the removed contact if found.
    pub fn remove(&mut self, id: &NodeId) -> Option<Contact> {
        match &mut self.content {
            ZoneContent::Leaf(bin) => bin.remove(id),
            ZoneContent::Branch { left, right } => {
                let bit = id.bit(self.depth);
                if bit {
                    right.remove(id)
                } else {
                    left.remove(id)
                }
            }
        }
    }

    /// Find a contact by ID.
    pub fn get(&self, id: &NodeId) -> Option<&Contact> {
        match &self.content {
            ZoneContent::Leaf(bin) => bin.iter().find(|c| &c.id == id),
            ZoneContent::Branch { left, right } => {
                let bit = id.bit(self.depth);
                if bit { right.get(id) } else { left.get(id) }
            }
        }
    }

    /// Count total contacts in this zone and all children.
    pub fn count(&self) -> usize {
        match &self.content {
            ZoneContent::Leaf(bin) => bin.len(),
            ZoneContent::Branch { left, right } => left.count() + right.count(),
        }
    }

    /// Whether this zone may be split.
    fn can_split(&self, total_contacts: usize, max_table_size: usize) -> bool {
        // Condition 1: depth < 127
        if self.depth >= 127 {
            return false;
        }
        // Condition 2: total < max
        if total_contacts >= max_table_size {
            return false;
        }
        // Condition 3: oracle `CanSplit` keeps splitting the low-index zones
        // and the whole tree up to `KBASE`, regardless of our own node ID.
        if self.depth < KBASE as u32 || self.zone_index < KK {
            return true;
        }
        false
    }

    /// Split a leaf into two child zones, redistributing contacts.
    fn split(&mut self) {
        let bin = match &mut self.content {
            ZoneContent::Leaf(b) => {
                let mut drained = RoutingBin::new();
                for c in b.drain() {
                    let _ = drained.try_add(c);
                }
                drained
            }
            ZoneContent::Branch { .. } => return, // already split
        };

        let depth = self.depth;
        let mut left = Box::new(RoutingZone::new_leaf(
            depth + 1,
            child_zone_index(self.zone_index, false),
        ));
        let mut right = Box::new(RoutingZone::new_leaf(
            depth + 1,
            child_zone_index(self.zone_index, true),
        ));

        for c in bin.iter() {
            let bit = c.id.bit(depth);
            if bit {
                // We use a large max_table_size here since we're just redistributing
                let _ = right.add(c.clone(), 0, usize::MAX);
            } else {
                let _ = left.add(c.clone(), 0, usize::MAX);
            }
        }

        self.content = ZoneContent::Branch { left, right };
    }
}

fn child_zone_index(parent_zone_index: usize, right_child: bool) -> usize {
    let child_zone_index = parent_zone_index
        .saturating_mul(2)
        .saturating_add(usize::from(right_child));
    child_zone_index.min(KK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::Contact;
    use overlord_kad_proto::{K, NodeId};
    use std::net::Ipv4Addr;

    fn make_contact(id_bytes: [u8; 16], ip: &str) -> Contact {
        Contact::new(
            NodeId::from_bytes(id_bytes),
            ip.parse::<Ipv4Addr>().unwrap(),
            4672,
            4662,
            9,
        )
    }

    #[test]
    fn test_add_and_count() {
        let mut zone = RoutingZone::new_root();
        for i in 0..5u8 {
            let mut id = [0u8; 16];
            id[0] = i + 1;
            // Use distinct /24 subnets to avoid per-bin subnet limit
            let c = make_contact(id, &format!("1.{}.0.1", i + 1));
            zone.add(c, i as usize, 1000).unwrap();
        }
        assert_eq!(zone.count(), 5);
    }

    #[test]
    fn test_get_closest_all_contacts() {
        let mut zone = RoutingZone::new_root();
        for i in 1..=5u8 {
            let mut id = [0u8; 16];
            id[0] = i;
            let c = make_contact(id, &format!("10.0.0.{}", i));
            zone.add(c, i as usize, 1000).unwrap();
        }
        let mut result = Vec::new();
        let target = NodeId::from_bytes([0x00; 16]);
        zone.get_closest(&target, 10, &mut result);
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_remove() {
        let mut zone = RoutingZone::new_root();
        let id = NodeId::from_bytes([0x01; 16]);
        let c = make_contact([0x01; 16], "1.1.1.1");
        zone.add(c, 0, 1000).unwrap();
        assert_eq!(zone.count(), 1);
        let removed = zone.remove(&id);
        assert!(removed.is_some());
        assert_eq!(zone.count(), 0);
    }

    #[test]
    fn test_split_on_overflow() {
        // own_id starts with 0x00, so bit 0 = 0 → own side is left (bit=0)
        let mut zone = RoutingZone::new_root();

        // Add K contacts with bit 0 = 0 (same side as own_id)
        // Use distinct /24 subnets to avoid per-bin subnet limit
        for i in 0..K as u8 {
            let mut id = [0x00u8; 16];
            id[1] = i + 1; // all have bit 0 = 0
            let c = make_contact(id, &format!("1.{}.0.1", i + 1));
            zone.add(c, i as usize, 10000).unwrap();
        }
        assert_eq!(zone.count(), K);

        // Adding one more on the same side should trigger a split
        let mut extra_id = [0x00u8; 16];
        extra_id[2] = 1;
        let extra = make_contact(extra_id, "1.99.0.1");
        let result = zone.add(extra, K, 10000);
        // After split, it should succeed
        assert!(result.is_ok());
        assert_eq!(zone.count(), K + 1);
    }

    #[test]
    fn test_get_by_id() {
        let mut zone = RoutingZone::new_root();
        let id = NodeId::from_bytes([0xAB; 16]);
        let c = make_contact([0xAB; 16], "9.9.9.9");
        zone.add(c, 0, 1000).unwrap();
        assert!(zone.get(&id).is_some());
        assert!(zone.get(&NodeId::ZERO).is_none());
    }

    fn make_id_with_bit(depth: u32, wanted_bit: bool, discriminator: u8) -> [u8; 16] {
        for candidate in 0u8..=u8::MAX {
            let mut id = [0u8; 16];
            id[0] = candidate;
            id[15] = discriminator;
            if NodeId::from_bytes(id).bit(depth) == wanted_bit {
                return id;
            }
        }
        panic!("failed to find id for depth={depth} wanted_bit={wanted_bit}");
    }

    fn make_full_leaf(depth: u32, zone_index: usize, right_contacts: usize) -> RoutingZone {
        let mut zone = RoutingZone {
            depth,
            zone_index,
            content: ZoneContent::Leaf(RoutingBin::new()),
        };
        for i in 0..K as u8 {
            let wants_right_child = usize::from(i >= (K - right_contacts) as u8) != 0;
            let id = make_id_with_bit(depth, wants_right_child, i + 1);
            let contact = make_contact(id, &format!("20.{}.0.1", i + 1));
            let _ = zone.add(contact, i as usize, usize::MAX);
        }
        zone
    }

    #[test]
    fn test_zone_index_below_kk_still_splits_after_kbase() {
        let mut zone = make_full_leaf(KBASE as u32, KK - 1, 1);
        let extra = make_contact(make_id_with_bit(KBASE as u32, true, 200), "21.1.0.1");

        let result = zone.add(extra, K, usize::MAX);

        assert!(result.is_ok());
        assert_eq!(zone.count(), K + 1);
    }

    #[test]
    fn test_zone_index_at_kk_stops_splitting_after_kbase() {
        let mut zone = make_full_leaf(KBASE as u32, KK, 0);
        let extra = make_contact(make_id_with_bit(KBASE as u32, false, 201), "22.1.0.1");

        let result = zone.add(extra, K, usize::MAX);

        assert!(matches!(result, Err(RoutingError::TableFull { .. })));
        assert_eq!(zone.count(), K);
    }
}
