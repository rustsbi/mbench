//! Functional conformance check runner (`conformance/*`), cleanly decoupled from timing.

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
    Pass {
        checks: u64,
        total: u64,
        issues: CheckIssues,
        note: Option<&'static str>,
    },
    Skipped(SkipReason),
    Failed {
        checks: u64,
        total: u64,
        failed: u64,
        primary: FailReason,
        issues: CheckIssues,
        note: Option<&'static str>,
    },
}

/// Declarative functional conformance check case descriptor.
pub struct CheckCase<Env> {
    pub meta: CheckMeta,
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
        self.total += 1;
        if cond {
            self.passed += 1;
            true
        } else {
            self.failed += 1;
            self.issues.push(CheckIssue {
                label,
                class: IssueClass::SpecViolation,
                reason: FailReason::AssertionFailed(label),
            });
            false
        }
    }

    /// Evaluates a normative assertion annotated with a known firmware quirk (still fails if false).
    pub fn expect_with_quirk(
        &mut self,
        cond: bool,
        label: &'static str,
        quirk: &'static str,
    ) -> bool {
        self.total += 1;
        if cond {
            self.passed += 1;
            true
        } else {
            self.failed += 1;
            self.issues.push(CheckIssue {
                label,
                class: IssueClass::SpecViolationWithQuirk(quirk),
                reason: FailReason::AssertionFailed(label),
            });
            false
        }
    }

    /// Asserts that raw SBI error code `actual` equals `expected` without short-circuiting.
    pub fn expect_sbi_err(&mut self, actual: isize, expected: isize, label: &'static str) -> bool {
        self.total += 1;
        if actual == expected {
            self.passed += 1;
            true
        } else {
            self.failed += 1;
            self.issues.push(CheckIssue {
                label,
                class: IssueClass::SpecViolation,
                reason: FailReason::UnexpectedSbiError(actual),
            });
            false
        }
    }

    /// Asserts that raw SBI error code `actual` belongs to `allowed` without short-circuiting.
    pub fn expect_sbi_err_in(
        &mut self,
        actual: isize,
        allowed: &[isize],
        label: &'static str,
    ) -> bool {
        self.total += 1;
        if allowed.contains(&actual) {
            self.passed += 1;
            true
        } else {
            self.failed += 1;
            self.issues.push(CheckIssue {
                label,
                class: IssueClass::SpecViolation,
                reason: FailReason::UnexpectedSbiError(actual),
            });
            false
        }
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
        self.total += 1;
        if actual == expected {
            self.passed += 1;
            true
        } else {
            self.failed += 1;
            let class = if actual == quirk_code {
                IssueClass::SpecViolationWithQuirk(quirk)
            } else {
                IssueClass::SpecViolation
            };
            self.issues.push(CheckIssue {
                label,
                class,
                reason: FailReason::UnexpectedSbiError(actual),
            });
            false
        }
    }

    /// Enforces a prerequisite needed for safe execution of subsequent checks; aborts only if false.
    pub fn require(&mut self, cond: bool, label: &'static str) -> Result<(), RequireFailed> {
        if self.expect(cond, label) {
            Ok(())
        } else {
            Err(RequireFailed)
        }
    }

    /// Enforces an arbitrary fallible prerequisite; aborts only if `res` is `Err`, preserving reason.
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
        self.total += 1;
        self.passed += 1;
    }

    /// Records one failed assertion with an explicit structured [`FailReason`].
    pub fn record_fail(&mut self, label: &'static str, reason: FailReason) {
        self.total += 1;
        self.failed += 1;
        self.issues.push(CheckIssue {
            label,
            class: IssueClass::SpecViolation,
            reason,
        });
    }

    /// Records one quirk-annotated failure with an explicit [`FailReason`].
    pub fn record_quirk_fail(
        &mut self,
        label: &'static str,
        reason: FailReason,
        quirk: &'static str,
    ) {
        self.total += 1;
        self.failed += 1;
        self.issues.push(CheckIssue {
            label,
            class: IssueClass::SpecViolationWithQuirk(quirk),
            reason,
        });
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
        if class.is_failure() {
            self.total += 1;
            self.failed += 1;
        }
        self.issues.push(CheckIssue {
            label,
            class,
            reason,
        });
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
    #[cfg(not(feature = "std"))]
    extern crate std;

    #[cfg(not(feature = "std"))]
    use std::string::String;

    use super::*;
    use crate::{
        config::RunConfig,
        record::{MAX_CHECK_ISSUES, SbiCapMask},
    };

    struct DummyTopo;

    impl HartTopology for DummyTopo {
        fn total_harts(&self) -> usize {
            1
        }
    }

    fn ok_check(_env: &mut DummyTopo) -> CheckOutcome {
        let mut ctx = CheckCtx::new();
        ctx.expect(true, "trivial");
        ctx.record_pass();
        ctx.finish()
    }

    fn bad_check_continues(_env: &mut DummyTopo) -> CheckOutcome {
        let mut ctx = CheckCtx::new();
        ctx.expect(true, "first_ok");
        ctx.expect(false, "bad_ret");
        ctx.expect_with_quirk(false, "quirk_ret", "opensbi-quirk");
        ctx.expect(true, "last_ok");
        ctx.finish()
    }

    fn aborted_check(_env: &mut DummyTopo) -> CheckOutcome {
        let mut ctx = CheckCtx::new();
        ctx.expect(true, "pre_ok");
        if ctx.require(false, "precond_missing").is_err() {
            return ctx.finish();
        }
        ctx.expect(true, "unreachable");
        ctx.finish()
    }

    #[test]
    fn executes_groups_aggregates_issues_and_enforces_require_and_flags() {
        let group_a = CheckGroup {
            name: "a",
            cases: &[
                CheckCase {
                    meta: CheckMeta::new("conformance/base", None, 1, CaseFlags::empty()),
                    run: ok_check,
                },
                CheckCase {
                    meta: CheckMeta::new(
                        "conformance/sse",
                        Some(SbiExtensionId::Sse),
                        1,
                        CaseFlags::empty(),
                    ),
                    run: ok_check,
                },
                CheckCase {
                    meta: CheckMeta::new("conformance/susp", None, 1, CaseFlags::DESTRUCTIVE),
                    run: ok_check,
                },
            ],
        };
        let group_b = CheckGroup {
            name: "b",
            cases: &[
                CheckCase {
                    meta: CheckMeta::new("conformance/multi_fail", None, 1, CaseFlags::empty()),
                    run: bad_check_continues,
                },
                CheckCase {
                    meta: CheckMeta::new("conformance/aborted", None, 1, CaseFlags::empty()),
                    run: aborted_check,
                },
            ],
        };

        let mut env = DummyTopo;
        let mut state = RunState::new(RunConfig::default(), SbiCapMask::BASE);
        let mut out = String::new();
        let mut q_calls = 0usize;
        execute_check_groups(&[group_a, group_b], &mut env, &mut state, &mut out, |_| {
            q_calls += 1;
            0
        });

        assert_eq!(state.summary.checks_total, 5);
        assert_eq!(state.summary.checks_passed, 1);
        assert_eq!(state.summary.checks_skipped, 2);
        assert_eq!(state.summary.checks_failed, 2);
        // 2 ok + (2 passed, 2 failed) + (1 passed, 1 failed) => total=8, passed=5, failed=3
        assert_eq!(state.summary.check_assertions_total, 8);
        assert_eq!(state.summary.check_assertions_passed, 5);
        assert_eq!(state.summary.check_assertions_failed, 3);
        assert_eq!(q_calls, 3);
        assert!(out.contains(
            "\"id\":\"conformance/base\",\"checks\":2,\"checks_total\":2,\"checks_failed\":0,\"status\":\"PASS\""
        ));
        assert!(out.contains("\"skip_reason\":\"extension_unsupported\""));
        assert!(out.contains("\"skip_reason\":\"requires_destructive_flag\""));
        assert!(
            out.contains("\"checks\":2,\"checks_total\":4,\"checks_failed\":2,\"status\":\"FAIL\"")
        );
        assert!(out.contains("\"quirks\":1"));
        assert!(out.contains("\"quirk\":\"opensbi-quirk\""));
        assert!(out.contains("\"fail_reason\":\"assert:precond_missing\""));
        assert!(!out.contains("unreachable"));
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
