//! Host-only significance comparisons using the existing statistics dependency.

use anofox_statistics::{Alternative, mann_whitney_u};

/// Classification of the two-sample comparison between candidate and baseline distributions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffVerdict {
    /// Candidate median is smaller with a significant distribution difference.
    Faster,
    /// Candidate median is larger with a significant distribution difference.
    Slower,
    /// The test did not detect a significant distribution difference.
    NoSignificantDiff,
    /// Distributions differ significantly despite equal reported medians.
    DistributionDiff,
    /// Both sample sets contain the same single value.
    Identical,
    /// Fewer than five samples per group, or the statistical test could not run.
    InsufficientSamples,
}

/// Result of comparing candidate samples against baseline samples using Mann-Whitney U.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SampleComparison {
    /// Candidate median divided by the baseline median, absent when the baseline is zero.
    pub ratio: Option<f64>,
    /// Two-sided Mann-Whitney U p-value, absent when comparison is unavailable.
    pub p_value: Option<f64>,
    /// Significance and direction of the sample comparison.
    pub verdict: DiffVerdict,
}

/// Compares two per-trial sample slices using `anofox_statistics::mann_whitney_u` (`alpha = 0.05`).
///
/// Uses the exact permutation distribution when tie-free and small, or the tie-corrected
/// continuity-corrected normal approximation when ties exist.
pub fn compare_samples(
    base_median_x100: u64,
    cand_median_x100: u64,
    base: &[u64],
    cand: &[u64],
) -> SampleComparison {
    let ratio =
        (base_median_x100 > 0).then(|| (cand_median_x100 as f64) / (base_median_x100 as f64));

    if base.len() < 5 || cand.len() < 5 {
        return SampleComparison {
            ratio,
            p_value: None,
            verdict: DiffVerdict::InsufficientSamples,
        };
    }

    let first = base[0];
    if base.iter().all(|&v| v == first) && cand.iter().all(|&v| v == first) {
        return SampleComparison {
            ratio,
            p_value: Some(1.0),
            verdict: DiffVerdict::Identical,
        };
    }

    let base_f: Vec<f64> = base.iter().map(|&v| v as f64).collect();
    let cand_f: Vec<f64> = cand.iter().map(|&v| v as f64).collect();
    let Ok(res) = mann_whitney_u(
        &base_f,
        &cand_f,
        Alternative::TwoSided,
        true,
        true,
        None,
        None,
    ) else {
        return SampleComparison {
            ratio,
            p_value: None,
            verdict: DiffVerdict::InsufficientSamples,
        };
    };

    let p_value = res.p_value.clamp(0.0, 1.0);
    let verdict = if p_value < 0.05 {
        if cand_median_x100 < base_median_x100 {
            DiffVerdict::Faster
        } else if cand_median_x100 > base_median_x100 {
            DiffVerdict::Slower
        } else {
            DiffVerdict::DistributionDiff
        }
    } else {
        DiffVerdict::NoSignificantDiff
    };

    SampleComparison {
        ratio,
        p_value: Some(p_value),
        verdict,
    }
}
