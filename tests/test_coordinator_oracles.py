from __future__ import annotations

from dataclasses import replace

import pytest

from heraclitus_attack import coordinator as coordinator_module
from heraclitus_attack import executor as executor_module
from heraclitus_attack.catalog import full_plans, plans_for_profile, smoke_plans
from heraclitus_attack.config import BudgetConfig, RuntimeConfig, SafetyConfig
from heraclitus_attack.coordinator import CampaignReport, Coordinator
from heraclitus_attack.executor import SafeToolExecutor
from heraclitus_attack.models import (
    AttackPlan,
    AttackStep,
    Finding,
    Observation,
    OracleResult,
    RiskLevel,
    UntrustedData,
    Verdict,
)
from heraclitus_attack.oracles import (
    AvailabilityOracle,
    EvidenceReceiptOracle,
    HttpStatusOracle,
    OracleRegistry,
    ReachabilityOracle,
    SensitiveLeakOracle,
    UpstreamEffectOracle,
    default_oracles,
)
from heraclitus_attack.safety import (
    SafetyViolation,
    effective_plan_requires_authorization,
)
from heraclitus_attack.settings import CampaignSettings, LabSettings


TARGET = "http://127.0.0.1:7475"


def runtime(**budget_overrides: object) -> RuntimeConfig:
    return RuntimeConfig(
        budgets=BudgetConfig(**budget_overrides),
        safety=SafetyConfig(
            allowed_tools=frozenset({"http_request"}),
            allowed_targets=frozenset({TARGET}),
        ),
        user_agent="coordinator-test",
    )


def step(*, step_id: str = "step-proposed", target: str = TARGET) -> AttackStep:
    return AttackStep(
        step_id=step_id,
        tool="http_request",
        target=target,
        operation="probe",
        arguments={"method": "GET", "path": "/healthz"},
        timeout_seconds=1,
    )


def plan(
    *,
    oracle_ids: tuple[str, ...] = ("fixed",),
    steps: tuple[AttackStep, ...] | None = None,
    metadata: dict[str, object] | None = None,
) -> AttackPlan:
    return AttackPlan(
        plan_id="plan-proposed",
        campaign_id="campaign-proposed",
        title="deterministic boundary probe",
        hypothesis="the independent invariant remains true",
        risk=RiskLevel.SAFE,
        steps=steps or (step(),),
        oracle_ids=oracle_ids,
        metadata=metadata or {},
    )


def observation(
    *,
    step_id: str = "step-observed",
    tool: str = "http_request",
    status_code: int | None = None,
    ok: bool = True,
    evidence: dict[str, object] | None = None,
    body: bytes | None = None,
) -> Observation:
    return Observation(
        step_id=step_id,
        tool=tool,
        target=TARGET,
        started_at="2026-09-20T00:00:00+00:00",
        duration_ms=1,
        ok=ok,
        status_code=status_code,
        untrusted_response=(
            UntrustedData.from_bytes(body, content_type="application/json")
            if body is not None
            else None
        ),
        evidence=evidence or {},
    )


class ScriptedExecutor:
    def __init__(
        self,
        config: RuntimeConfig,
        *,
        error: Exception | None = None,
    ) -> None:
        self.config = config
        self.error = error
        self.calls: list[AttackPlan] = []

    def execute_plan(self, candidate: AttackPlan, *, authorization=None):
        del authorization
        self.calls.append(candidate)
        if self.error is not None:
            raise self.error
        return tuple(observation(step_id=item.step_id) for item in candidate.steps)


class ScriptedOracle:
    oracle_id = "fixed"

    def __init__(self, *outcomes: OracleResult | Exception) -> None:
        self.outcomes = outcomes
        self.calls = 0

    def evaluate(self, candidate, observations):
        del candidate, observations
        outcome = self.outcomes[min(self.calls, len(self.outcomes) - 1)]
        self.calls += 1
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class Proposer:
    def __init__(self, proposed) -> None:
        self.proposed = proposed
        self.contexts = []

    def propose(self, context):
        self.contexts.append(context)
        return self.proposed


def oracle_result(
    verdict: Verdict,
    *,
    fingerprint: str | None = None,
    oracle_id: str = "fixed",
) -> OracleResult:
    return OracleResult(
        oracle_id=oracle_id,
        verdict=verdict,
        reason=f"deterministic {verdict.value}",
        evidence_fingerprint=fingerprint,
    )


@pytest.mark.parametrize(
    "oracle_verdict",
    [Verdict.PASS, Verdict.INCONCLUSIVE, Verdict.ERROR],
)
def test_coordinator_preserves_non_failure_verdicts_and_rebinds_ids(oracle_verdict):
    config = runtime()
    executor = ScriptedExecutor(config)
    oracle = ScriptedOracle(oracle_result(oracle_verdict))
    finding = Coordinator(
        executor=executor,
        oracles={"fixed": oracle},
        config=config,
    ).run_plan(plan(), campaign_id="campaign-trusted")

    assert finding.verdict is oracle_verdict
    assert finding.attempts == 1
    assert finding.confirmations == 0
    assert executor.calls[0].campaign_id == "campaign-trusted"
    assert executor.calls[0].plan_id != "plan-proposed"
    assert executor.calls[0].steps[0].step_id != "step-proposed"
    assert executor.calls[0].metadata["proposed_plan_id"] == "plan-proposed"


def test_coordinator_promotes_only_three_identical_failures_to_vulnerable():
    config = runtime(confirmation_runs=3)
    executor = ScriptedExecutor(config)
    oracle = ScriptedOracle(oracle_result(Verdict.FAIL, fingerprint="stable"))

    finding = Coordinator(
        executor=executor,
        oracles={"fixed": oracle},
        config=config,
    ).run_plan(plan())

    assert finding.verdict is Verdict.VULNERABLE
    assert finding.attempts == 3
    assert finding.confirmations == 3
    assert len(finding.oracle_results) == 3
    assert len(executor.calls) == 3
    assert "reproduced 3/3" in finding.reason


def test_coordinator_does_not_promote_an_unstable_failure():
    config = runtime(confirmation_runs=3)
    executor = ScriptedExecutor(config)
    oracle = ScriptedOracle(
        oracle_result(Verdict.FAIL, fingerprint="first"),
        oracle_result(Verdict.FAIL, fingerprint="changed"),
    )

    finding = Coordinator(
        executor=executor,
        oracles={"fixed": oracle},
        config=config,
    ).run_plan(plan())

    assert finding.verdict is Verdict.FAIL
    assert finding.attempts == 2
    assert finding.confirmations == 1
    assert "not promoted" in finding.reason


def test_coordinator_does_not_replay_failure_without_typed_fingerprint():
    config = runtime(confirmation_runs=3)
    executor = ScriptedExecutor(config)
    oracle = ScriptedOracle(oracle_result(Verdict.FAIL))

    finding = Coordinator(
        executor=executor,
        oracles={"fixed": oracle},
        config=config,
    ).run_plan(plan())

    assert finding.verdict is Verdict.FAIL
    assert finding.attempts == 1
    assert finding.confirmations == 0


def test_coordinator_fails_closed_for_missing_oracle_without_execution():
    config = runtime()
    executor = ScriptedExecutor(config)
    finding = Coordinator(executor=executor, oracles={}, config=config).run_plan(
        plan(oracle_ids=("missing",))
    )

    assert finding.verdict is Verdict.ERROR
    assert finding.attempts == 0
    assert finding.oracle_results[0].oracle_id == "missing"
    assert executor.calls == []


def test_coordinator_reports_safety_rejection_without_calling_an_oracle():
    config = runtime()
    executor = ScriptedExecutor(config, error=SafetyViolation("blocked by policy"))
    oracle = ScriptedOracle(oracle_result(Verdict.PASS))
    finding = Coordinator(
        executor=executor,
        oracles={"fixed": oracle},
        config=config,
    ).run_plan(plan())

    assert finding.verdict is Verdict.ERROR
    assert finding.attempts == 0
    assert finding.oracle_results == ()
    assert "safety gate" in finding.reason
    assert oracle.calls == 0


def test_coordinator_converts_oracle_exception_or_mismatched_id_to_error():
    config = runtime()
    for outcome in (
        RuntimeError("sensitive oracle detail"),
        oracle_result(Verdict.PASS, oracle_id="wrong"),
    ):
        executor = ScriptedExecutor(config)
        finding = Coordinator(
            executor=executor,
            oracles={"fixed": ScriptedOracle(outcome)},
            config=config,
        ).run_plan(plan())
        assert finding.verdict is Verdict.ERROR
        assert "sensitive oracle detail" not in finding.reason


def test_campaign_enforces_plan_count_and_proposer_oracle_separation():
    config = runtime(max_plans=1)
    executor = ScriptedExecutor(config)
    oracle = ScriptedOracle(oracle_result(Verdict.PASS))
    coordinator = Coordinator(
        executor=executor,
        oracles={"fixed": oracle},
        config=config,
    )
    with pytest.raises(SafetyViolation, match="plan budget"):
        coordinator.run_campaign(
            Proposer((plan(), plan())), target_hints={"rest": TARGET}
        )
    with pytest.raises(SafetyViolation, match="must be separate"):
        coordinator.run_campaign(oracle, target_hints={"rest": TARGET})


def test_campaign_stops_at_deadline_and_shares_trusted_campaign_id(monkeypatch):
    config = runtime(
        max_plans=3,
        step_timeout_seconds=0.25,
        plan_timeout_seconds=0.5,
        campaign_timeout_seconds=1,
    )
    executor = ScriptedExecutor(config)
    oracle = ScriptedOracle(oracle_result(Verdict.PASS))
    proposer = Proposer((plan(), plan()))
    ticks = iter((100.0, 100.1, 102.0, 102.1))
    monkeypatch.setattr(coordinator_module.time, "monotonic", lambda: next(ticks))

    report = Coordinator(
        executor=executor,
        oracles={"fixed": oracle},
        config=config,
    ).run_campaign(
        proposer,
        target_hints={"rest": TARGET},
        goals=("exercise invariant",),
    )

    assert len(report.findings) == 1
    assert report.findings[0].campaign_id == report.campaign_id
    assert proposer.contexts[0].campaign_id == report.campaign_id
    assert proposer.contexts[0].allowed_tools == ("http_request",)
    assert proposer.contexts[0].goals == ("exercise invariant",)


def test_campaign_report_uses_security_severity_order():
    def finding(verdict: Verdict) -> Finding:
        return Finding("c", "p", verdict.value, verdict, "reason", 1, 0, ())

    report = CampaignReport(
        campaign_id="c",
        started_at="now",
        duration_ms=1,
        findings=(finding(Verdict.PASS), finding(Verdict.FAIL), finding(Verdict.ERROR)),
    )
    assert report.verdict is Verdict.ERROR
    assert report.to_dict()["verdict"] == "error"
    assert CampaignReport("c", "now", 0, ()).verdict is Verdict.INCONCLUSIVE


class RecordingAdapter:
    def __init__(self) -> None:
        self.calls = []

    def execute(self, candidate, **kwargs):
        self.calls.append((candidate, kwargs))
        return observation(step_id=candidate.step_id, status_code=200)


def test_executor_prevalidates_the_whole_plan_before_any_side_effect():
    config = runtime(max_steps_per_plan=2)
    adapter = RecordingAdapter()
    executor = SafeToolExecutor(config, registry={"http_request": adapter})
    unsafe = plan(
        steps=(
            step(step_id="safe-first"),
            step(step_id="unsafe-second", target="http://192.0.2.10:7475"),
        )
    )

    with pytest.raises(SafetyViolation, match="loopback"):
        executor.execute_plan(unsafe)
    assert adapter.calls == []


def test_executor_turns_request_budget_exhaustion_into_an_observation():
    config = runtime(max_steps_per_plan=2, max_requests_per_plan=1)
    adapter = RecordingAdapter()
    executor = SafeToolExecutor(config, registry={"http_request": adapter})
    result = executor.execute_plan(
        plan(steps=(step(step_id="one"), step(step_id="two")))
    )

    assert len(adapter.calls) == 1
    assert len(result) == 2
    assert result[0].ok
    assert not result[1].ok
    assert result[1].error == "request budget exhausted"


def test_executor_enforces_deadline_and_bounds_adapter_call(monkeypatch):
    config = runtime(
        step_timeout_seconds=0.25,
        plan_timeout_seconds=0.5,
        campaign_timeout_seconds=1,
    )
    adapter = RecordingAdapter()
    executor = SafeToolExecutor(config, registry={"http_request": adapter})
    ticks = iter((10.0, 11.0))
    monkeypatch.setattr(executor_module.time, "monotonic", lambda: next(ticks))

    result = executor.execute_plan(plan(steps=(replace(step(), timeout_seconds=0.25),)))

    assert not result[0].ok
    assert result[0].error == "plan deadline exceeded"
    assert adapter.calls == []


def test_executor_rejects_registry_outside_allowlist():
    with pytest.raises(ValueError, match="non-allowlisted"):
        SafeToolExecutor(runtime(), registry={"tcp_probe": RecordingAdapter()})


def test_http_status_oracle_filters_tools_and_handles_inconclusive_status():
    oracle = HttpStatusOracle()
    candidate = plan(
        oracle_ids=(oracle.oracle_id,),
        metadata={
            "expected_statuses": [200],
            "inconclusive_statuses": [401],
            "status_tools": ["http_request"],
        },
    )
    filtered = oracle.evaluate(
        candidate,
        (
            observation(tool="mcp_call", status_code=500),
            observation(tool="http_request", status_code=200),
        ),
    )
    blocked = oracle.evaluate(
        candidate, (observation(tool="http_request", status_code=401),)
    )

    assert filtered.verdict is Verdict.PASS
    assert filtered.details["observed_statuses"] == [200]
    assert blocked.verdict is Verdict.INCONCLUSIVE


@pytest.mark.parametrize(
    "metadata, observations, expected",
    [
        ({}, (), Verdict.INCONCLUSIVE),
        ({"expected_statuses": ["bad"]}, (), Verdict.ERROR),
        (
            {"expected_statuses": [200], "inconclusive_statuses": ["bad"]},
            (observation(status_code=200),),
            Verdict.ERROR,
        ),
        (
            {"expected_statuses": [200], "unexpected_status_is_vulnerability": True},
            (observation(status_code=500),),
            Verdict.VULNERABLE,
        ),
    ],
)
def test_http_status_oracle_fail_closed_paths(metadata, observations, expected):
    result = HttpStatusOracle().evaluate(
        plan(oracle_ids=("http_status",), metadata=metadata), observations
    )
    assert result.verdict is expected


@pytest.mark.parametrize(
    "values, expected",
    [
        ((), Verdict.INCONCLUSIVE),
        ((True,), Verdict.PASS),
        ((True, False), Verdict.VULNERABLE),
    ],
)
def test_availability_oracle(values, expected):
    observations = tuple(observation(evidence={"health": value}) for value in values)
    assert AvailabilityOracle().evaluate(plan(), observations).verdict is expected


@pytest.mark.parametrize(
    "evidence_values, expected",
    [
        ((), Verdict.INCONCLUSIVE),
        ((1,), Verdict.INCONCLUSIVE),
        ((True, True), Verdict.PASS),
        ((True, False), Verdict.INCONCLUSIVE),
    ],
)
def test_reachability_oracle_requires_typed_probe(evidence_values, expected):
    observations = tuple(
        observation(evidence={"reachable": value}) for value in evidence_values
    )
    result = ReachabilityOracle().evaluate(plan(), observations)
    assert result.verdict is expected


@pytest.mark.parametrize(
    "counters, expected",
    [
        ((3,), Verdict.INCONCLUSIVE),
        ((3, 2), Verdict.INCONCLUSIVE),
        ((3, 3), Verdict.PASS),
        ((3, 5), Verdict.VULNERABLE),
    ],
)
def test_upstream_effect_oracle_uses_counter_delta(counters, expected):
    observations = tuple(observation(evidence={"counter": value}) for value in counters)
    result = UpstreamEffectOracle().evaluate(plan(), observations)
    assert result.verdict is expected


def test_upstream_effect_fingerprint_is_stable_across_absolute_counters():
    oracle = UpstreamEffectOracle()
    first = oracle.evaluate(
        plan(),
        (observation(evidence={"counter": 5}), observation(evidence={"counter": 7})),
    )
    second = oracle.evaluate(
        plan(),
        (observation(evidence={"counter": 20}), observation(evidence={"counter": 22})),
    )
    assert first.verdict is second.verdict is Verdict.VULNERABLE
    assert first.evidence_fingerprint == second.evidence_fingerprint


def test_sensitive_leak_oracle_requires_canary_and_body_then_detects_leak():
    oracle = SensitiveLeakOracle()
    no_canary = oracle.evaluate(plan(), (observation(body=b"safe"),))
    candidate = plan(metadata={"forbidden_markers": ["SYNTHETIC-CANARY"]})
    no_body = oracle.evaluate(candidate, (observation(),))
    clean = oracle.evaluate(candidate, (observation(body=b'{"value":"safe"}'),))
    leaked = oracle.evaluate(
        candidate,
        (observation(body=b'{"value":"SYNTHETIC-CANARY"}'),),
    )

    assert no_canary.verdict is Verdict.INCONCLUSIVE
    assert no_body.verdict is Verdict.INCONCLUSIVE
    assert clean.verdict is Verdict.PASS
    assert leaked.verdict is Verdict.VULNERABLE
    assert leaked.details["match_count"] == 1


def test_evidence_receipt_oracle_correlates_native_ids():
    oracle = EvidenceReceiptOracle()
    absent = oracle.evaluate(plan(), (observation(evidence={"status": "ok"}),))
    present = oracle.evaluate(
        plan(),
        (
            observation(evidence={"lsn": 42}),
            observation(evidence={"evidence_id": "receipt-7"}),
        ),
    )
    assert absent.verdict is Verdict.INCONCLUSIVE
    assert present.verdict is Verdict.PASS
    assert present.details["receipt_count"] == 2


def test_oracle_registry_rejects_duplicates_resolves_and_evaluates():
    with pytest.raises(ValueError, match="unique"):
        OracleRegistry((HttpStatusOracle(), HttpStatusOracle()))

    registry = OracleRegistry()
    expected_ids = tuple(sorted(item.oracle_id for item in default_oracles()))
    assert registry.ids == expected_ids
    assert registry.resolve("reachability").oracle_id == "reachability"
    with pytest.raises(KeyError, match="not registered"):
        registry.resolve("missing")

    results = registry.evaluate(
        plan(oracle_ids=("reachability",)),
        (observation(evidence={"reachable": True}),),
    )
    assert len(results) == 1
    assert results[0].verdict is Verdict.PASS


def test_catalog_smoke_and_full_profiles_are_bounded_and_curated():
    settings = LabSettings()
    smoke = smoke_plans(settings)
    full = full_plans(settings)

    assert len(smoke) == 6
    assert len(full) == 9
    assert [item.title for item in full[: len(smoke)]] == [
        item.title for item in smoke
    ]
    assert all(not item.destructive for item in full)
    assert all(
        candidate.steps
        and all(step_.tool in settings.runtime.safety.allowed_tools for step_ in candidate.steps)
        and all(step_.target in settings.runtime.safety.allowed_targets for step_ in candidate.steps)
        for candidate in full
    )
    assert any("path traversal" in item.title.lower() for item in smoke)
    assert any(item.oracle_ids == ("http_status", "upstream_zero") for item in smoke)
    assert any("synthetic ssrf" in item.title.lower() for item in smoke)
    assert any("prompt injection" in item.title.lower() for item in full)
    assert all(not effective_plan_requires_authorization(item) for item in smoke)
    assert any(effective_plan_requires_authorization(item) for item in full)


def test_catalog_profile_selector_uses_smoke_or_full_set():
    smoke_settings = LabSettings(campaign=CampaignSettings(profile="smoke"))
    full_settings = replace(
        smoke_settings,
        campaign=replace(smoke_settings.campaign, profile="full"),
    )
    assert len(plans_for_profile(smoke_settings)) == 6
    assert len(plans_for_profile(full_settings)) == 9
