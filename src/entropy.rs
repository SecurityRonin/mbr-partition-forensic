//! Shannon entropy over byte slices.
//!
//! Used to classify slack regions: entropy ≈ 0.0 → all-zero/wiped;
//! entropy < 1.0 → low variety (e.g., repeated pattern); entropy > 6.0
//! → likely compressed, encrypted, or random data.

/// Entropy (bits/byte) above which a slack region is treated as likely
/// data-bearing — compressed, encrypted, or random rather than padding.
/// This is the single threshold the severity model consults for slack.
pub const HIGH_ENTROPY_THRESHOLD: f64 = 6.0;

/// Compute the Shannon entropy (bits per byte, range 0.0–8.0) of `data`.
///
/// Returns `0.0` for an empty slice.
#[must_use]
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Returns `true` if `data` is entirely one repeated byte value.
#[must_use]
pub fn is_uniform(data: &[u8]) -> bool {
    data.windows(2).all(|w| w[0] == w[1])
}
