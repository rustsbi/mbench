//! Functional conformance checks, independent of performance measurement.

use core::fmt::Write;

use crate::{
    protocol,
    record::{
        CaseFlags, CaseGate, CheckIssue, CheckIssues, CheckResult, CheckStatus, FailReason,
        HartTopology, IssueClass, RunState, SbiExtensionId, SkipReason, StartKind,
    },
};

/// Static metadata describing one functional conformance suite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckMeta {
    pub id: &'static str,
    /// Capabilities and explicit permissions required before execution.
    pub gate: CaseGate,
}

impl CheckMeta {
    /// Creates conformance metadata from `id`, `required_ext`, `min_harts`, and `flags`.
    pub const fn new(
        id: &'static str,
        required_ext: Option<SbiExtensionId>,
        min_harts: usize,
        flags: CaseFlags,
    ) -> Self {
        Self {
            id,
            gate: CaseGate::new(required_ext, min_harts, flags),
        }
    }
}

/// Outcome returned by a functional conformance check routine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckOutcome {
    /// All executed assertions passed.
    Pass {
        /// Number of passed assertions in this check.
        checks: u64,
        /// Number of assertions evaluated, including failures.
        total: u64,
        /// Retained assertion failures and observations.
        issues: CheckIssues,
        note: Option<&'static str>,
    },
    /// Execution was skipped for the enclosed reason.
    Skipped(SkipReason),
    /// One or more assertions or prerequisites failed.
    Failed {
        /// Number of passed assertions in this check.
        checks: u64,
        /// Number of assertions evaluated, including failures.
        total: u64,
        failed: u64,
        /// First retained normative failure, used as the case failure reason.
        primary: FailReason,
        /// Retained assertion failures and observations.
        issues: CheckIssues,
        note: Option<&'static str>,
    },
}

/// Declarative functional conformance check case descriptor.
pub struct CheckCase<Env> {
    /// Static metadata controlling case gating.
    pub meta: CheckMeta,
    /// Conformance callback invoked after its gates pass.
    pub run: fn(&mut Env) -> CheckOutcome,
}

impl<Env> Clone for CheckCase<Env> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Env> Copy for CheckCase<Env> {}

/// Logical group of conformance cases registered together while executed independently.
pub struct CheckGroup<'a, Env: 'a> {
    pub name: &'static str,
    /// Cases executed independently in registration order.
    pub cases: &'a [CheckCase<Env>],
}

impl<'a, Env: 'a> Clone for CheckGroup<'a, Env> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, Env: 'a> Copy for CheckGroup<'a, Env> {}

/// Zero-sized signal returned by [`CheckCtx::require`] / [`CheckCtx::require_ok`] to abort a case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequireFailed;

/// Non-short-circuiting assertion and observation accumulator for one conformance case.
#[derive(Clone, Copy, Debug, Default)]
pub struct CheckCtx {
    total: u64,
    passed: u64,
    failed: u64,
    issues: CheckIssues,
    note: Option<&'static str>,
}

impl CheckCtx {
    fn record_assertion(&mut self, failure: Option<CheckIssue>) -> bool {
        self.total += 1;
        if let Some(issue) = failure {
            self.failed += 1;
            self.issues.push(issue);
            false
        } else {
            self.passed += 1;
            true
        }
    }

    /// Creates an empty conformance context.
    pub const fn new() -> Self {
        Self {
            total: 0,
            passed: 0,
            failed: 0,
            issues: CheckIssues::new(),
            note: None,
        }
    }

    /// Evaluates one normative assertion without short-circuiting the remaining checks.
    pub fn expect(&mut self, cond: bool, label: &'static str) -> bool {
        self.record_assertion((!cond).then_some(CheckIssue {
            label,
            class: IssueClass::SpecViolation,
            reason: FailReason::AssertionFailed(label),
        }))
    }

    /// Evaluates a normative assertion annotated with a known firmware quirk (still fails if false).
    pub fn expect_with_quirk(
        &mut self,
        cond: bool,
        label: &'static str,
        quirk: &'static str,
    ) -> bool {
        self.record_assertion((!cond).then_some(CheckIssue {
            label,
            class: IssueClass::SpecViolationWithQuirk(quirk),
            reason: FailReason::AssertionFailed(label),
        }))
    }

    /// Asserts that raw SBI error code `actual` equals `expected` without short-circuiting.
    pub fn expect_sbi_err(&mut self, actual: isize, expected: isize, label: &'static str) -> bool {
        self.record_assertion((actual != expected).then_some(CheckIssue {
            label,
            class: IssueClass::SpecViolation,
            reason: FailReason::UnexpectedSbiError(actual),
        }))
    }

    /// Asserts that raw SBI error code `actual` belongs to `allowed` without short-circuiting.
    pub fn expect_sbi_err_in(
        &mut self,
        actual: isize,
        allowed: &[isize],
        label: &'static str,
    ) -> bool {
        self.record_assertion((!allowed.contains(&actual)).then_some(CheckIssue {
            label,
            class: IssueClass::SpecViolation,
            reason: FailReason::UnexpectedSbiError(actual),
        }))
    }

    /// Evaluates an error expectation where one specific error code indicates a known firmware quirk.
    pub fn expect_sbi_err_quirk(
        &mut self,
        actual: isize,
        expected: isize,
        quirk_code: isize,
        quirk: &'static str,
        label: &'static str,
    ) -> bool {
        let class = if actual == quirk_code {
            IssueClass::SpecViolationWithQuirk(quirk)
        } else {
            IssueClass::SpecViolation
        };
        self.record_assertion((actual != expected).then_some(CheckIssue {
            label,
            class,
            reason: FailReason::UnexpectedSbiError(actual),
        }))
    }

    /// Enforces a prerequisite needed for safe execution of subsequent checks; aborts only if false.
    ///
    /// # Errors
    ///
    /// Records a failed assertion and returns `RequireFailed` when `cond` is false.
    pub fn require(&mut self, cond: bool, label: &'static str) -> Result<(), RequireFailed> {
        if self.expect(cond, label) {
            Ok(())
        } else {
            Err(RequireFailed)
        }
    }

    /// Enforces an arbitrary fallible prerequisite; aborts only if `res` is `Err`, preserving reason.
    ///
    /// # Errors
    ///
    /// Records the supplied failure and returns `RequireFailed` when `res` is an error.
    /// A successful prerequisite does not increment assertion counts.
    pub fn require_ok(
        &mut self,
        res: Result<(), FailReason>,
        label: &'static str,
    ) -> Result<(), RequireFailed> {
        match res {
            Ok(()) => Ok(()),
            Err(reason) => {
                self.record_fail(label, reason);
                Err(RequireFailed)
            }
        }
    }

    /// Records one externally verified assertion toward passed and total counts.
    pub fn record_pass(&mut self) {
        self.record_assertion(None);
    }

    /// Records one failed assertion with an explicit structured [`FailReason`].
    pub fn record_fail(&mut self, label: &'static str, reason: FailReason) {
        self.record_assertion(Some(CheckIssue {
            label,
            class: IssueClass::SpecViolation,
            reason,
        }));
    }

    /// Records one quirk-annotated failure with an explicit [`FailReason`].
    pub fn record_quirk_fail(
        &mut self,
        label: &'static str,
        reason: FailReason,
        quirk: &'static str,
    ) {
        self.record_assertion(Some(CheckIssue {
            label,
            class: IssueClass::SpecViolationWithQuirk(quirk),
            reason,
        }));
    }

    /// Records a structured observation or issue; failures still update failure tallies.
    pub fn observe(&mut self, label: &'static str, class: IssueClass) {
        self.observe_with_reason(label, class, FailReason::AssertionFailed(label));
    }

    /// Records an observation or issue preserving an explicit `reason`.
    pub fn observe_with_reason(
        &mut self,
        label: &'static str,
        class: IssueClass,
        reason: FailReason,
    ) {
        let issue = CheckIssue {
            label,
            class,
            reason,
        };
        if class.is_failure() {
            self.record_assertion(Some(issue));
        } else {
            self.issues.push(issue);
        }
    }

    /// Attaches an optional human-readable note emitted on the `@@MBENCH:CHECK` frame.
    pub fn set_note(&mut self, note: &'static str) {
        self.note = Some(note);
    }

    /// Returns current failure tally.
    pub const fn failed_count(&self) -> u64 {
        self.failed
    }

    /// Finalizes the context as `Failed` if any violation occurred, or `Pass` otherwise.
    pub fn finish(self) -> CheckOutcome {
        if self.failed > 0 || self.issues.has_failure() {
            let primary = self
                .issues
                .first_failure()
                .map_or(FailReason::VerificationMismatch, |i| i.reason);
            CheckOutcome::Failed {
                checks: self.passed,
                total: self.total,
                failed: self.failed.max(1),
                primary,
                issues: self.issues,
                note: self.note,
            }
        } else {
            CheckOutcome::Pass {
                checks: self.passed,
                total: self.total,
                issues: self.issues,
                note: self.note,
            }
        }
    }

    /// Returns `Skipped(skip)` only when zero assertions ran and zero failures occurred.
    pub fn finish_or_skip(self, skip: SkipReason) -> CheckOutcome {
        if self.failed > 0 || self.issues.has_failure() || self.total > 0 {
            self.finish()
        } else {
            CheckOutcome::Skipped(skip)
        }
    }
}

/// Executes a slice of functional conformance checks, emitting `@@MBENCH:CHECK` frames and running `quarantine_fn`.
pub fn execute_checks<Env: HartTopology>(
    cases: &[CheckCase<Env>],
    env: &mut Env,
    state: &mut RunState<'_>,
    out: &mut (impl Write + ?Sized),
    mut quarantine_fn: impl FnMut(&mut Env) -> usize,
) {
    for case in cases {
        run_single_check(case, env, state, out, &mut quarantine_fn);
    }
}

/// Executes multiple logical [`CheckGroup`] slices sequentially while gating each [`CheckCase`] independently.
pub fn execute_check_groups<Env: HartTopology>(
    groups: &[CheckGroup<'_, Env>],
    env: &mut Env,
    state: &mut RunState<'_>,
    out: &mut (impl Write + ?Sized),
    mut quarantine_fn: impl FnMut(&mut Env) -> usize,
) {
    for group in groups {
        for case in group.cases {
            run_single_check(case, env, state, out, &mut quarantine_fn);
        }
    }
}

/// Emits a synthetic check record (such as secondary-hart bringup failure) honoring common gates.
pub fn emit_synthetic_check_result(
    id: &'static str,
    label: &'static str,
    reason: FailReason,
    note: Option<&'static str>,
    state: &mut RunState<'_>,
    out: &mut (impl Write + ?Sized),
) {
    let mut issues = CheckIssues::new();
    issues.push(CheckIssue {
        label,
        class: IssueClass::SpecViolation,
        reason,
    });
    let _ = protocol::write_start_line(StartKind::Check, id, 1, out);
    emit_check_result(
        &CheckResult {
            id,
            checks: 0,
            checks_total: 1,
            checks_failed: 1,
            status: CheckStatus::Failed(reason),
            issues,
            quirks: 0,
            note,
        },
        state,
        out,
    );
}

fn run_single_check<Env: HartTopology>(
    case: &CheckCase<Env>,
    env: &mut Env,
    state: &mut RunState<'_>,
    out: &mut (impl Write + ?Sized),
    quarantine_fn: &mut impl FnMut(&mut Env) -> usize,
) {
    let meta = &case.meta;
    if let Some(reason) = state.check_common_gates(meta.id, meta.gate, env.total_harts()) {
        emit_check_result(
            &CheckResult {
                id: meta.id,
                checks: 0,
                checks_total: 0,
                checks_failed: 0,
                status: CheckStatus::Skipped(reason),
                issues: CheckIssues::new(),
                quirks: 0,
                note: None,
            },
            state,
            out,
        );
        return;
    }

    let _ = protocol::write_start_line(StartKind::Check, meta.id, 1, out);
    let outcome = (case.run)(env);
    let warns = quarantine_fn(env);
    state.summary.quarantine_warnings = state.summary.quarantine_warnings.saturating_add(warns);

    let res = match outcome {
        CheckOutcome::Pass {
            checks,
            total,
            issues,
            note,
        } => {
            let quirks = issues.quirk_count();
            CheckResult {
                id: meta.id,
                checks,
                checks_total: total.max(checks),
                checks_failed: 0,
                status: CheckStatus::Pass,
                issues,
                quirks,
                note,
            }
        }
        CheckOutcome::Skipped(reason) => CheckResult {
            id: meta.id,
            checks: 0,
            checks_total: 0,
            checks_failed: 0,
            status: CheckStatus::Skipped(reason),
            issues: CheckIssues::new(),
            quirks: 0,
            note: None,
        },
        CheckOutcome::Failed {
            checks,
            total,
            failed,
            primary,
            issues,
            note,
        } => {
            let quirks = issues.quirk_count();
            CheckResult {
                id: meta.id,
                checks,
                checks_total: total.max(checks.saturating_add(failed)),
                checks_failed: failed,
                status: CheckStatus::Failed(primary),
                issues,
                quirks,
                note,
            }
        }
    };
    emit_check_result(&res, state, out);
}

fn emit_check_result(
    res: &CheckResult<'_>,
    state: &mut RunState<'_>,
    out: &mut (impl Write + ?Sized),
) {
    state.summary.checks_total = state.summary.checks_total.saturating_add(1);
    match res.status {
        CheckStatus::Pass => state.summary.checks_passed += 1,
        CheckStatus::Skipped(_) => state.summary.checks_skipped += 1,
        CheckStatus::Failed(_) => state.summary.checks_failed += 1,
    }
    state.summary.check_assertions_total = state
        .summary
        .check_assertions_total
        .saturating_add(res.checks_total);
    state.summary.check_assertions_passed = state
        .summary
        .check_assertions_passed
        .saturating_add(res.checks);
    state.summary.check_assertions_failed = state
        .summary
        .check_assertions_failed
        .saturating_add(res.checks_failed);
    let _ = protocol::write_check_progress(res, out);
    let _ = protocol::write_check_line(res, out);
}

#[cfg(test)]
mod tests {
    use super::{CheckCtx, CheckOutcome};
    use crate::{
        config::RunConfig,
        record::{
            CaseFlags, CaseGate, FailReason, IssueClass, MAX_CHECK_ISSUES, RunState, SbiCapMask,
            SbiExtensionId, SkipReason,
        },
    };

    #[test]
    fn counts_assertions_and_preserves_prerequisite_semantics() {
        let mut ctx = CheckCtx::new();
        assert!(ctx.expect(true, "first_ok"));
        assert!(!ctx.expect(false, "bad_ret"));
        assert!(!ctx.expect_with_quirk(false, "quirk_ret", "opensbi-quirk"));
        assert!(ctx.require_ok(Ok(()), "ready").is_ok());
        ctx.observe("permitted", IssueClass::PermittedBehavior);
        assert!(ctx.require(false, "precond_missing").is_err());
        match ctx.finish() {
            CheckOutcome::Failed {
                checks,
                total,
                failed,
                issues,
                primary,
                ..
            } => {
                assert_eq!((checks, total, failed), (1, 4, 3));
                assert_eq!(issues.quirk_count(), 1);
                assert_eq!(primary, FailReason::AssertionFailed("bad_ret"));
            }
            other => panic!("expected Failed outcome, got {other:?}"),
        }
        let mut ctx = CheckCtx::new();
        ctx.observe("unsupported", IssueClass::Unsupported);
        assert_eq!(
            ctx.finish_or_skip(SkipReason::FunctionUnsupported),
            CheckOutcome::Skipped(SkipReason::FunctionUnsupported)
        );
    }

    #[test]
    fn common_gates_preserve_filter_capability_and_safety_order() {
        let mut state = RunState::new(RunConfig::default(), SbiCapMask::BASE);
        assert_eq!(
            state.check_common_gates("base", CaseGate::new(None, 1, CaseFlags::empty()), 1),
            None
        );
        assert_eq!(
            state.check_common_gates(
                "sse",
                CaseGate::new(Some(SbiExtensionId::Sse), 1, CaseFlags::empty()),
                1
            ),
            Some(SkipReason::ExtensionUnsupported)
        );
        assert_eq!(
            state.check_common_gates("susp", CaseGate::new(None, 1, CaseFlags::DESTRUCTIVE), 1),
            Some(SkipReason::RequiresDestructiveFlag)
        );
    }

    #[test]
    fn fixed_capacity_issues_prioritize_failures_on_overflow() {
        let mut ctx = CheckCtx::new();
        for _ in 0..MAX_CHECK_ISSUES {
            ctx.observe("note_obs", IssueClass::PermittedBehavior);
        }
        ctx.expect(false, "real_failure");
        let outcome = ctx.finish();
        match outcome {
            CheckOutcome::Failed {
                issues, primary, ..
            } => {
                assert!(issues.is_truncated());
                assert!(issues.has_failure());
                assert_eq!(primary, FailReason::AssertionFailed("real_failure"));
            }
            other => panic!("expected Failed outcome, got {other:?}"),
        }
    }
}
