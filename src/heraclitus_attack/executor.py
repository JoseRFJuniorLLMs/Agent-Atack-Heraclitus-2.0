"""Budgeted execution of safety-gated plans."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Mapping

from .config import RuntimeConfig
from .models import AttackPlan, AttackStep, Observation, utc_now
from .safety import DestructiveAuthorization, SafetyGate, SafetyViolation
from .tools import ToolAdapter, default_tool_registry


class ExecutionBudgetExceeded(RuntimeError):
    pass


@dataclass(slots=True)
class ExecutionSession:
    deadline: float
    requests_used: int = 0


class SafeToolExecutor:
    """Execute only registered adapters after a fail-closed validation pass."""

    def __init__(
        self,
        config: RuntimeConfig | None = None,
        *,
        registry: Mapping[str, ToolAdapter] | None = None,
        gate: SafetyGate | None = None,
    ) -> None:
        self.config = config or RuntimeConfig()
        self.gate = gate or SafetyGate(self.config)
        self._registry = dict(registry or default_tool_registry())
        unapproved = set(self._registry) - self.config.safety.allowed_tools
        if unapproved:
            raise ValueError(f"registry contains non-allowlisted tools: {sorted(unapproved)}")

    def new_session(self) -> ExecutionSession:
        return ExecutionSession(
            deadline=time.monotonic() + self.config.budgets.plan_timeout_seconds
        )

    def execute_step(
        self,
        step: AttackStep,
        *,
        session: ExecutionSession | None = None,
        authorization: DestructiveAuthorization | None = None,
    ) -> Observation:
        self.gate.validate_step(step)
        if step.destructive:
            self.gate.validate_destructive_authorization(authorization)
        active = session or self.new_session()
        if active.requests_used >= self.config.budgets.max_requests_per_plan:
            raise ExecutionBudgetExceeded("request budget exhausted")
        remaining = active.deadline - time.monotonic()
        if remaining <= 0:
            raise ExecutionBudgetExceeded("plan deadline exceeded")
        adapter = self._registry.get(step.tool)
        if adapter is None:
            raise SafetyViolation(f"no trusted adapter registered for {step.tool!r}")
        active.requests_used += 1
        requested = step.timeout_seconds or self.config.budgets.step_timeout_seconds
        timeout = min(
            requested,
            self.config.budgets.step_timeout_seconds,
            remaining,
        )
        return adapter.execute(
            step,
            timeout_seconds=timeout,
            max_response_bytes=self.config.budgets.max_response_bytes,
            user_agent=self.config.user_agent,
        )

    def execute_plan(
        self,
        plan: AttackPlan,
        *,
        authorization: DestructiveAuthorization | None = None,
    ) -> tuple[Observation, ...]:
        # Validate the complete plan before the first network side effect.
        self.gate.validate_plan(plan, authorization)
        session = self.new_session()
        observations: list[Observation] = []
        for step in plan.steps:
            try:
                observations.append(
                    self.execute_step(
                        step, session=session, authorization=authorization
                    )
                )
            except ExecutionBudgetExceeded as exc:
                observations.append(
                    Observation(
                        step_id=step.step_id,
                        tool=step.tool,
                        target=step.target,
                        started_at=utc_now(),
                        duration_ms=0.0,
                        ok=False,
                        error=str(exc),
                    )
                )
                break
        return tuple(observations)

