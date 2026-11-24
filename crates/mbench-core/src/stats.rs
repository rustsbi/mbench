//! Nonparametric per-operation summary statistics, derived ns scaling, and host Mann-Whitney U comparison.

/// Maximum number of outer trials supported on stack across all profiles.
pub const MAX_TRIALS: usize = 21;

/// Fixed-point multiplier (`100x`) used by [`CounterStats`] and [`DerivedNsStats`] so `no_std` targets avoid floats.
pub const STATS_SCALE: u64 = 100;

/// Nonparametric per-operation statistics (`STATS_SCALE = 100`) plus raw and net per-trial samples.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterStats {
    /// Minimum net per-operation value multiplied by 100.
    pub min_x100: u64,
    /// Net per-operation value at sorted index n / 4, multiplied by 100.
    pub p25_x100: u64,
    /// Net per-operation value at sorted index n / 2, multiplied by 100.
    pub median_x100: u64,
    /// Net per-operation value at sorted index 3n / 4, multiplied by 100.
    pub p75_x100: u64,
    /// Net per-operation value at sorted index (n - 1) * 95 / 100, multiplied by 100.
    pub p95_x100: u64,
    /// Maximum net per-operation value multiplied by 100.
    pub max_x100: u64,
    /// Interquartile range of net per-operation values multiplied by 100.
    pub iqr_x100: u64,
    /// Median unsubtracted batch total in native counter units.
    pub raw_batch_median: u64,
    /// Whether the positive median has an interquartile range greater than 5% of it.
    pub is_noisy: bool,
    /// Number of populated chronological sample slots.
    pub sample_count: usize,
    /// Chronological unsubtracted per-trial batch totals in native counter units.
    pub raw_batch_totals: [u64; MAX_TRIALS],
    /// Chronological overhead-subtracted per-operation samples multiplied by 100.
    pub net_samples_x100: [u64; MAX_TRIALS],
}

impl Default for CounterStats {
    fn default() -> Self {
        Self {
            min_x100: 0,
            p25_x100: 0,
            median_x100: 0,
            p75_x100: 0,
            p95_x100: 0,
            max_x100: 0,
            iqr_x100: 0,
            raw_batch_median: 0,
            is_noisy: false,
            sample_count: 0,
            raw_batch_totals: [0; MAX_TRIALS],
            net_samples_x100: [0; MAX_TRIALS],
        }
    }
}

impl CounterStats {
    /// Returns chronological unsubtracted per-trial batch totals (in native counter units).
    pub fn raw_batch_totals(&self) -> &[u64] {
        let len = self.sample_count.min(MAX_TRIALS);
        &self.raw_batch_totals[..len]
    }

    /// Returns chronological overhead-subtracted per-operation values scaled by [`STATS_SCALE`].
    pub fn net_samples_x100(&self) -> &[u64] {
        let len = self.sample_count.min(MAX_TRIALS);
        &self.net_samples_x100[..len]
    }
}

/// Nanosecond summary statistics derived solely from net tick samples and FDT `timebase-frequency`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivedNsStats {
    /// Minimum net per-operation value multiplied by 100.
    pub min_x100: u64,
    /// Net per-operation value at sorted index n / 4, multiplied by 100.
    pub p25_x100: u64,
    /// Net per-operation value at sorted index n / 2, multiplied by 100.
    pub median_x100: u64,
    /// Net per-operation value at sorted index 3n / 4, multiplied by 100.
    pub p75_x100: u64,
    /// Net per-operation value at sorted index (n - 1) * 95 / 100, multiplied by 100.
    pub p95_x100: u64,
    /// Maximum net per-operation value multiplied by 100.
    pub max_x100: u64,
    /// Interquartile range of net per-operation values multiplied by 100.
    pub iqr_x100: u64,
    /// Noise classification inherited from the original tick samples.
    pub is_noisy: bool,
    /// Number of populated chronological sample slots.
    pub sample_count: usize,
    /// Chronological overhead-subtracted per-operation samples multiplied by 100.
    pub net_samples_x100: [u64; MAX_TRIALS],
}

impl Default for DerivedNsStats {
    fn default() -> Self {
        Self {
            min_x100: 0,
            p25_x100: 0,
            median_x100: 0,
            p75_x100: 0,
            p95_x100: 0,
            max_x100: 0,
            iqr_x100: 0,
            is_noisy: false,
            sample_count: 0,
            net_samples_x100: [0; MAX_TRIALS],
        }
    }
}

impl DerivedNsStats {
    /// Returns chronological net per-operation nanoseconds scaled by [`STATS_SCALE`].
    pub fn net_samples_x100(&self) -> &[u64] {
        let len = self.sample_count.min(MAX_TRIALS);
        &self.net_samples_x100[..len]
    }
}

/// Computes nonparametric fixed-point statistics (`STATS_SCALE = 100`) with an explicit op count per trial.
pub fn compute_stats_per_trial(
    raw_totals: &[u64],
    ops_per_trial: &[u64],
    per_op_overhead_x100: u64,
    per_batch_overhead_x100: u64,
) -> CounterStats {
    let count = raw_totals.len().min(ops_per_trial.len()).min(MAX_TRIALS);
    if count == 0 {
        return CounterStats::default();
    }

    let mut raw_batch_totals = [0u64; MAX_TRIALS];
    let mut raw_sorted = [0u64; MAX_TRIALS];
    let mut net_samples_x100 = [0u64; MAX_TRIALS];
    let mut scaled_sorted = [0u64; MAX_TRIALS];

    for idx in 0..count {
        let divisor = ops_per_trial[idx];
        if divisor == 0 {
            return CounterStats::default();
        }
        let raw = raw_totals[idx];
        raw_batch_totals[idx] = raw;
        raw_sorted[idx] = raw;

        let total_overhead_x100 = (per_batch_overhead_x100 as u128)
            .saturating_add((per_op_overhead_x100 as u128).saturating_mul(divisor as u128));
        let raw_x100 = (raw as u128).saturating_mul(STATS_SCALE as u128);
        let net_x100 = raw_x100.saturating_sub(total_overhead_x100);
        let per_op = net_x100 / (divisor as u128);
        let scaled = u64::try_from(per_op).unwrap_or(u64::MAX);

        net_samples_x100[idx] = scaled;
        scaled_sorted[idx] = scaled;
    }

    raw_sorted[..count].sort_unstable();
    scaled_sorted[..count].sort_unstable();

    let raw_batch_median = raw_sorted[count / 2];
    let slice = &scaled_sorted[..count];
    let min_x100 = slice[0];
    let p25_x100 = slice[count / 4];
    let median_x100 = slice[count / 2];
    let p75_x100 = slice[(count * 3) / 4];
    let p95_idx = ((count - 1) * 95) / 100;
    let p95_x100 = slice[p95_idx];
    let max_x100 = slice[count - 1];
    let iqr_x100 = p75_x100.saturating_sub(p25_x100);
    let is_noisy = median_x100 > 0 && iqr_x100.saturating_mul(20) > median_x100;

    CounterStats {
        min_x100,
        p25_x100,
        median_x100,
        p75_x100,
        p95_x100,
        max_x100,
        iqr_x100,
        raw_batch_median,
        is_noisy,
        sample_count: count,
        raw_batch_totals,
        net_samples_x100,
    }
}

/// Computes nonparametric fixed-point statistics (`STATS_SCALE = 100`) for uniform `divisor` across trials.
pub fn compute_stats(
    raw_totals: &[u64],
    divisor: u64,
    per_op_overhead_x100: u64,
    per_batch_overhead_x100: u64,
) -> CounterStats {
    if divisor == 0 {
        return CounterStats::default();
    }
    let count = raw_totals.len().min(MAX_TRIALS);
    let ops = [divisor; MAX_TRIALS];
    compute_stats_per_trial(
        &raw_totals[..count],
        &ops[..count],
        per_op_overhead_x100,
        per_batch_overhead_x100,
    )
}

/// Converts scaled timer ticks (`STATS_SCALE = 100`) to scaled nanoseconds using `timebase_hz`.
pub fn ticks_to_ns_scaled(ticks_x100: u64, timebase_hz: u64) -> u64 {
    if timebase_hz == 0 {
        return 0;
    }
    let ns = (ticks_x100 as u128).saturating_mul(1_000_000_000u128) / (timebase_hz as u128);
    u64::try_from(ns).unwrap_or(u64::MAX)
}

/// Converts tick-based [`CounterStats`] into [`DerivedNsStats`] (without mixing raw tick counts).
pub fn scale_stats_to_ns(ticks: &CounterStats, timebase_hz: u64) -> DerivedNsStats {
    if timebase_hz == 0 {
        return DerivedNsStats::default();
    }
    let count = ticks.sample_count.min(MAX_TRIALS);
    let mut net_samples_x100 = [0u64; MAX_TRIALS];
    for (dst, &tick) in net_samples_x100
        .iter_mut()
        .zip(ticks.net_samples_x100.iter())
        .take(count)
    {
        *dst = ticks_to_ns_scaled(tick, timebase_hz);
    }
    DerivedNsStats {
        min_x100: ticks_to_ns_scaled(ticks.min_x100, timebase_hz),
        p25_x100: ticks_to_ns_scaled(ticks.p25_x100, timebase_hz),
        median_x100: ticks_to_ns_scaled(ticks.median_x100, timebase_hz),
        p75_x100: ticks_to_ns_scaled(ticks.p75_x100, timebase_hz),
        p95_x100: ticks_to_ns_scaled(ticks.p95_x100, timebase_hz),
        max_x100: ticks_to_ns_scaled(ticks.max_x100, timebase_hz),
        iqr_x100: ticks_to_ns_scaled(ticks.iqr_x100, timebase_hz),
        is_noisy: ticks.is_noisy,
        sample_count: count,
        net_samples_x100,
    }
}

#[cfg(feature = "std")]
pub use host::{DiffVerdict, SampleComparison, compare_samples};

#[cfg(feature = "std")]
mod host;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_raw_totals_and_chronological_net_samples() {
        let clean = [1020, 1000, 1015, 1005, 1010];
        let stats = compute_stats(&clean, 10, 0, 10);
        assert_eq!(stats.raw_batch_median, 1010);
        assert_eq!(stats.raw_batch_totals(), &clean);
        assert_eq!(stats.median_x100, 10_099);
        assert!(!stats.is_noisy);
        assert_eq!(
            stats.net_samples_x100(),
            &[10_199, 9_999, 10_149, 10_049, 10_099]
        );

        let per_trial = compute_stats_per_trial(&[200, 300], &[10, 15], 0, 0);
        assert_eq!(per_trial.raw_batch_totals(), &[200, 300]);
        assert_eq!(per_trial.net_samples_x100(), &[2_000, 2_000]);

        let noisy = [100, 500, 1000, 1500, 2000];
        assert!(compute_stats(&noisy, 1, 0, 0).is_noisy);

        let ns = scale_stats_to_ns(&compute_stats(&[10, 20, 30, 40, 50], 1, 0, 0), 10_000_000);
        assert_eq!(ns.median_x100, 300_000);
        assert_eq!(
            ns.net_samples_x100(),
            &[100_000, 200_000, 300_000, 400_000, 500_000]
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn mann_whitney_distinguishes_exact_small_samples_ties_and_zero_baseline() {
        let identical = compare_samples(1200, 1200, &[1200; 5], &[1200; 5]);
        assert_eq!(identical.verdict, DiffVerdict::Identical);
        assert_eq!(identical.p_value, Some(1.0));
        assert_eq!(identical.ratio, Some(1.0));

        // Tie-free 5 vs 5 separated samples -> exact p = 2 / C(10,5) = 2 / 252 ~= 0.0079365.
        let exact_slower = compare_samples(12, 22, &[10, 11, 12, 13, 14], &[20, 21, 22, 23, 24]);
        assert_eq!(exact_slower.verdict, DiffVerdict::Slower);
        assert!((exact_slower.p_value.unwrap() - (2.0 / 252.0)).abs() < 1e-9);

        let icount_faster = compare_samples(1200, 800, &[1200; 5], &[800; 5]);
        assert_eq!(icount_faster.verdict, DiffVerdict::Faster);
        assert!(icount_faster.p_value.unwrap() < 0.05);

        let overlapping = compare_samples(
            1000,
            1015,
            &[980, 1000, 1010, 1030, 990, 1005],
            &[995, 1020, 1005, 1035, 985, 1015],
        );
        assert_eq!(overlapping.verdict, DiffVerdict::NoSignificantDiff);
        assert!(overlapping.p_value.unwrap() >= 0.05);

        let zero_base = compare_samples(0, 500, &[0; 5], &[500; 5]);
        assert_eq!(zero_base.ratio, None);
        assert_eq!(zero_base.verdict, DiffVerdict::Slower);

        let insufficient = compare_samples(1000, 500, &[1000; 4], &[500; 4]);
        assert_eq!(insufficient.verdict, DiffVerdict::InsufficientSamples);
        assert_eq!(insufficient.p_value, None);
    }
}
