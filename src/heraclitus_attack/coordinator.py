"""Campaign orchestration with a hard proposer/oracle trust boundary."""

from __future__ import annotations

from dataclasses import dataclass, replace
import time
from typing import Mapping, Protocol, Sequence

from .config import RuntimeConfig
from .executor import SafeToolExecutor
from .models import (
    AttackPlan,
    AttackStep,
    Finding,
    JsonValue,
    Observation,
    OracleResult,
    Verdict,
    new_id,
    utc_now,
)
from .safety import DestructiveAuthorization, SafetyViolation


@dataclass(frozen=True, slots=True)
class PlanningContext:
    """Trusted, response-free input exposed to a plan proposer.

    Observations and database response bodies are deliberately absent.  An
    adaptive implementation may feed back verdict codes or numeric coverage in
    a separate policy, but never raw target content.
    """

    campaign_id: str
    allowed_tools: tuple[str, ...]
    max_steps_per_plan: int
    target_hints: Mapping[str, str]
    goals: tuple[str, ...] = ()


class PlanProposer(Protocol):
    def propose(
        self, context: PlanningContext
    ) -> AttackPlan | Sequence[AttackPlan]: ...


class Oracle(Protocol):
    """Trusted deterministic judge, separate from the plan proposer."""

    oracle_id: str

    def evaluate(
        self, plan: AttackPlan, observations: Sequence[Observation]
    ) -> OracleResult: ...


@dataclass(frozen=True, slots=True)
class CampaignReport:
    campaign_id: str
    started_at: str
    duration_ms: float
    findings: tuple[Finding, ...]

    @property
    def verdict(self) -> Verdict:
        values = {item.verdict for item in self.findings}
        for candidate in (
            Verdict.VULNERABLE,
            Verdict.ERROR,
            Verdict.FAIL,
            Verdict.INCONCLUSIVE,
            Verdict.PASS,
        ):
            if candidate in values:
                return candidate
        return Verdict.INCONCLUSIVE

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "campaign_id": self.campaign_id,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "verdict": self.verdict.value,
            "findings": [item.to_dict() for item in self.findings],
        }


class Coordinator:
    """Runs typed plans and promotes only reproduced failures to vulnerabilities."""

    def __init__(
        self,
        *,
        executor: SafeToolExecutor,
        oracles: Mapping[str, Oracle],
        config: RuntimeConfig | None = None,
    ) -> None:
        self.executor = executor
        self.config = config or executor.config
        self.oracles = dict(oracles)
        for key, oracle in self.oracles.items():
            if key != oracle.oracle_id:
                raise ValueError(f"oracle registry key mismatch: {key!r}")

    @staticmethod
    def _bind_plan(plan: AttackPlan, campaign_id: str) -> AttackPlan:
        """Replace all proposer-controlled correlation IDs with UUID-backed IDs."""

        proposed_id = plan.plan_id
        metadata = dict(plan.metadata)
        metadata.setdefault("proposed_plan_id", proposed_id)
        steps = tuple(
            replace(step, step_id=new_id("step")) for step in plan.steps
        )
        return replace(
            plan,
            plan_id=new_id("plan"),
            campaign_id=campaign_id,
            steps=steps,
            metadata=metadata,
        )

    def _evaluate(
        self, plan: AttackPlan, observations: Sequence[Observation]
    ) -> tuple[OracleResult, ...]:
        results: list[OracleResult] = []
        for oracle_id in plan.oracle_ids:
            oracle = self.oracles.get(oracle_id)
            if oracle is None:
                results.append(
                    OracleResult(
                        oracle_id=oracle_id,
                        verdict=Verdict.ERROR,
                        reason="required oracle is not registered",
                    )
                )
                continue
            try:
                result = oracle.evaluate(plan, observations)
                if result.oracle_id != oracle_id:
                    raise ValueError("oracle returned a mismatched ID")
                results.append(result)
            except Exception as exc:  # oracle is trusted code, but must fail closed
                results.append(
                    OracleResult(
                        oracle_id=oracle_id,
                        verdict=Verdict.ERROR,
                        reason=f"oracle evaluation failed: {type(exc).__name__}",
                    )
                )
        return tuple(results)

    @staticmethod
    def _base_verdict(results: Sequence[OracleResult]) -> Verdict:
        verdicts = {result.verdict for result in results}
        if Verdict.VULNERABLE in verdicts or Verdict.FAIL in verdicts:
            return Verdict.FAIL
        if Verdict.ERROR in verdicts:
            return Verdict.ERROR
        if Verdict.INCONCLUSIVE in verdicts:
            return Verdict.INCONCLUSIVE
        if results and verdicts == {Verdict.PASS}:
            return Verdict.PASS
        return Verdict.INCONCLUSIVE

    @staticmethod
    def _failure_keys(results: Sequence[OracleResult]) -> set[tuple[str, str]]:
        return {
            (item.oracle_id, item.evidence_fingerprint)
            for item in results
            if item.verdict in {Verdict.FAIL, Verdict.VULNERABLE}
            and item.evidence_fingerprint
        }

    def run_plan(
        self,
        plan: AttackPlan,
        *,
        campaign_id: str | None = None,
        authorization: DestructiveAuthorization | None = None,
    ) -> Finding:
        campaign = campaign_id or new_id("campaign")
        bound = self._bind_plan(plan, campaign)
        missing = [name for name in bound.oracle_ids if name not in self.oracles]
        if missing:
            results = tuple(
                OracleResult(name, Verdict.ERROR, "required oracle is not registered")
                for name in missing
            )
            return Finding(
                campaign_id=campaign,
                plan_id=bound.plan_id,
                title=bound.title,
                verdict=Verdict.ERROR,
                reason=f"missing oracle(s): {', '.join(missing)}",
                attempts=0,
                confirmations=0,
                oracle_results=results,
            )

        all_results: list[OracleResult] = []
        attempts = 0
        try:
            observations = self.executor.execute_plan(
                bound, authorization=authorization
            )
        except SafetyViolation as exc:
            return Finding(
                campaign_id=campaign,
                plan_id=bound.plan_id,
                title=bound.title,
                verdict=Verdict.ERROR,
                reason=f"plan rejected by safety gate: {exc}",
                attempts=0,
                confirmations=0,
                oracle_results=(),
            )
        attempts += 1
        first_results = self._evaluate(bound, observations)
        all_results.extend(first_results)
        base = self._base_verdict(first_results)

        if base is not Verdict.FAIL:
            reason = "; ".join(item.reason for item in first_results)
            return Finding(
                campaign_id=campaign,
                plan_id=bound.plan_id,
                title=bound.title,
                verdict=base,
                reason=reason or "no decisive oracle result",
                attempts=attempts,
                confirmations=0,
                oracle_results=tuple(all_results),
            )

        required = self.config.budgets.confirmation_runs
        stable_keys = self._failure_keys(first_results)
        confirmations = 1 if stable_keys else 0
        while stable_keys and attempts < required:
            try:
                observations = self.executor.execute_plan(
                    bound, authorization=authorization
                )
            except SafetyViolation:
                break
            attempts += 1
            repeated = self._evaluate(bound, observations)
            all_results.extend(repeated)
            repeated_keys = self._failure_keys(repeated)
            stable_keys &= repeated_keys
            if stable_keys:
                confirmations += 1

        if stable_keys and confirmations >= required:
            verdict = Verdict.VULNERABLE
            reason = (
                f"deterministic invariant violation reproduced {confirmations}/"
                f"{attempts} times by an independent oracle"
            )
        else:
            verdict = Verdict.FAIL
            reason = (
                "invariant violation observed but not promoted: stable, typed "
                "oracle evidence did not meet the reproduction threshold"
            )
        return Finding(
            campaign_id=campaign,
            plan_id=bound.plan_id,
            title=bound.title,
            verdict=verdict,
            reason=reason,
            attempts=attempts,
            confirmations=confirmations,
            oracle_results=tuple(all_results),
        )

    def run_campaign(
        self,
        proposer: PlanProposer,
        *,
        target_hints: Mapping[str, str],
        goals: Sequence[str] = (),
        authorization: DestructiveAuthorization | None = None,
    ) -> CampaignReport:
        if any(proposer is oracle for oracle in self.oracles.values()):
            raise SafetyViolation("plan proposer and deterministic oracle must be separate")
        campaign_id = new_id("campaign")
        started_at = utc_now()
        started = time.monotonic()
        context = PlanningContext(
            campaign_id=campaign_id,
            allowed_tools=tuple(sorted(self.config.safety.allowed_tools)),
            max_steps_per_plan=self.config.budgets.max_steps_per_plan,
            target_hints=dict(target_hints),
            goals=tuple(goals),
        )
        proposed = proposer.propose(context)
        plans = (proposed,) if isinstance(proposed, AttackPlan) else tuple(proposed)
        if len(plans) > self.config.budgets.max_plans:
            raise SafetyViolation("proposer exceeded campaign plan budget")
        if any(not isinstance(plan, AttackPlan) for plan in plans):
            raise TypeError("proposer must return AttackPlan objects")

        findings: list[Finding] = []
        campaign_deadline = started + self.config.budgets.campaign_timeout_seconds
        for plan in plans:
            if time.monotonic() >= campaign_deadline:
                break
            findings.append(
                self.run_plan(
                    plan,
                    campaign_id=campaign_id,
                    authorization=authorization,
                )
            )
        return CampaignReport(
            campaign_id=campaign_id,
            started_at=started_at,
            duration_ms=(time.monotonic() - started) * 1000,
            findings=tuple(findings),
        )
