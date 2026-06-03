//! Internal diagnostics — a single, greppable home for every trace event.
//!
//! By default these are zero-cost no-ops, so the crate carries no logging
//! dependency. Enable the `trace` feature to forward every event to the
//! [`tracing`](https://docs.rs/tracing) ecosystem for structured,
//! level-filtered debugging of analysis runs over untrusted images.
//!
//! Keeping all diagnostics here (rather than scattered macros) means the full
//! set of observable events is discoverable in one place, and the analysis
//! code reads as plain control flow.

use crate::boot_code::BootCodeId;
use crate::findings::Anomaly;
use crate::Error;

/// An anomaly was recorded by the analysis.
#[cfg(feature = "trace")]
pub(crate) fn anomaly_recorded(a: &Anomaly) {
    tracing::debug!(
        code = a.code,
        severity = %a.severity,
        offset = a.offset,
        note = %a.note,
        "anomaly recorded"
    );
}
#[cfg(not(feature = "trace"))]
#[inline]
pub(crate) fn anomaly_recorded(_a: &Anomaly) {}

/// The analysis finished; summary counts.
#[cfg(feature = "trace")]
pub(crate) fn analysis_complete(
    anomalies: usize,
    partitions: usize,
    gaps: usize,
    boot: BootCodeId,
) {
    tracing::debug!(anomalies, partitions, gaps, boot_code = ?boot, "analysis complete");
}
#[cfg(not(feature = "trace"))]
#[inline]
pub(crate) fn analysis_complete(
    _anomalies: usize,
    _partitions: usize,
    _gaps: usize,
    _boot: BootCodeId,
) {
}

/// Walking the EBR chain of an extended partition failed (e.g. a seek error).
#[cfg(feature = "trace")]
pub(crate) fn ebr_walk_failed(ext_start: u64, err: &Error) {
    tracing::warn!(ext_start, error = %err, "EBR chain walk failed");
}
#[cfg(not(feature = "trace"))]
#[inline]
pub(crate) fn ebr_walk_failed(_ext_start: u64, _err: &Error) {}

/// A partition's first sector could not be read for fingerprinting.
#[cfg(feature = "trace")]
pub(crate) fn partition_read_failed(byte_offset: u64, err: &Error) {
    tracing::trace!(byte_offset, error = %err, "could not read partition first sector");
}
#[cfg(not(feature = "trace"))]
#[inline]
pub(crate) fn partition_read_failed(_byte_offset: u64, _err: &Error) {}

/// An EBR sector could not be read (image truncated) — chain ends.
#[cfg(feature = "trace")]
pub(crate) fn ebr_truncated(ebr_lba: u64) {
    tracing::trace!(ebr_lba, "EBR read past end of image — chain ends");
}
#[cfg(not(feature = "trace"))]
#[inline]
pub(crate) fn ebr_truncated(_ebr_lba: u64) {}

/// An EBR sector lacked the `0x55AA` boot signature — chain ends.
#[cfg(feature = "trace")]
pub(crate) fn ebr_no_signature(ebr_lba: u64) {
    tracing::trace!(ebr_lba, "EBR has no 0x55AA signature — chain ends");
}
#[cfg(not(feature = "trace"))]
#[inline]
pub(crate) fn ebr_no_signature(_ebr_lba: u64) {}
