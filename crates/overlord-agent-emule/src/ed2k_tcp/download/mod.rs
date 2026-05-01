//! Active eD2k peer download support.

pub(in crate::ed2k_tcp) mod blocks;
pub(in crate::ed2k_tcp) mod window;

pub(in crate::ed2k_tcp) use blocks::{
    PendingCompressedPart, ReadyDownloadBlocks, flush_buffered_download_prefixes,
    flush_ready_download_blocks, reconcile_download_manifest_metadata,
};
pub(in crate::ed2k_tcp) use window::{
    ActiveDownloadPiece, DownloadRequestWindowState, PendingPartRequest,
    next_download_read_timeout, pump_download_request_window,
};
#[cfg(test)]
pub(in crate::ed2k_tcp) use window::{DownloadWindowLimits, select_download_window_limits};
