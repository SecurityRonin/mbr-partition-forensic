//! NT disk-signature (offset 440) cross-disk analysis.
//!
//! The 4-byte little-endian signature Windows writes at MBR offset 440 keys the
//! registry `MountedDevices` map and the Boot Configuration Data (BCD) store.
//! It is meant to be unique per physical disk. Two disks carrying the **same**
//! non-zero signature is a strong indicator that one was bit-for-bit **cloned**
//! or **imaged** from the other (Windows reacts by marking the duplicate
//! offline). This module surfaces such collisions across a set of disks.
//!
//! Single-disk signature checks (e.g. a Windows MBR whose signature is zero)
//! live in the analysis pipeline; this module is the cross-disk utility a
//! caller invokes after analysing several images.

/// A set of disks that share one non-zero NT disk signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SignatureCollision {
    /// The shared 4-byte signature value.
    pub signature: u32,
    /// Indices (into the caller's input slice) of every disk carrying it,
    /// in ascending order.
    pub members: Vec<usize>,
}

/// Find all NT disk-signature collisions across `signatures`.
///
/// `signatures[i]` is the signature of disk `i` (e.g. `MbrAnalysis::disk_serial`).
/// Returns one [`SignatureCollision`] per value shared by two or more disks,
/// ordered by first appearance. The zero signature is the "unset" convention
/// and is never treated as a shared identity.
#[must_use]
pub fn find_signature_collisions(signatures: &[u32]) -> Vec<SignatureCollision> {
    // Group input indices by signature, preserving first-seen order so the
    // output is deterministic without depending on hashing order.
    let mut order: Vec<u32> = Vec::new();
    let mut groups: std::collections::HashMap<u32, Vec<usize>> = std::collections::HashMap::new();
    for (i, &sig) in signatures.iter().enumerate() {
        if sig == 0 {
            continue;
        }
        let entry = groups.entry(sig).or_default();
        if entry.is_empty() {
            order.push(sig);
        }
        entry.push(i);
    }
    order
        .into_iter()
        .filter_map(|sig| {
            let members = groups.remove(&sig).unwrap_or_default();
            (members.len() >= 2).then_some(SignatureCollision {
                signature: sig,
                members,
            })
        })
        .collect()
}
