use crate::ed2k_server::Ed2kFoundSource;

pub(super) fn merge_download_sources(
    aggregated_sources: &mut Vec<Ed2kFoundSource>,
    new_sources: Vec<Ed2kFoundSource>,
) {
    for source in new_sources {
        if let Some(existing) = aggregated_sources.iter_mut().find(|existing| {
            existing.ip == source.ip
                && existing.tcp_port == source.tcp_port
                && existing.obfuscation_options == source.obfuscation_options
                && existing.user_hash == source.user_hash
        }) {
            if existing.source_server.is_none() && source.source_server.is_some() {
                existing.source_server = source.source_server;
            }
            continue;
        }
        aggregated_sources.push(source);
    }
}
