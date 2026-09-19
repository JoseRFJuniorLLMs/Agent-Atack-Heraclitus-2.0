"""Sequential, inspectable multi-agent planning pipeline."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Mapping

from ..memory import MemoryEvent, MemoryReceipt, MemorySink
from ..models import AttackPlan
from ..providers import LLMProvider
from .base import AgentContext
from .roles import CriticAgent, MinimizerAgent, MutatorAgent, PlannerAgent, ReconAgent


@dataclass(frozen=True, slots=True)
class PipelineStage:
    name: str
    plan: AttackPlan
    plan_sha256: str


@dataclass(frozen=True, slots=True)
class PipelineResult:
    plan: AttackPlan
    stages: tuple[PipelineStage, ...]
    memory_receipts: tuple[MemoryReceipt, ...] = ()


class AgentPipeline:
    """Recon -> plan -> critique -> mutate -> critique -> minimise.

    It only creates plans.  Execution and verdicts remain the responsibility of
    the coordinator, safety gate and deterministic oracle registry.
    """

    _ROLE_TYPES = {
        "recon": ReconAgent,
        "planner": PlannerAgent,
        "critic": CriticAgent,
        "mutator": MutatorAgent,
        "minimizer": MinimizerAgent,
    }

    def __init__(
        self,
        provider: LLMProvider | None = None,
        *,
        providers: Mapping[str, LLMProvider] | None = None,
        memory: MemorySink | None = None,
        temperature: float = 0.0,
    ) -> None:
        selected = dict(providers or {})
        if provider is None and set(selected) != set(self._ROLE_TYPES):
            missing = sorted(set(self._ROLE_TYPES) - set(selected))
            raise ValueError(f"providers missing roles: {missing}")
        unknown = set(selected) - set(self._ROLE_TYPES)
        if unknown:
            raise ValueError(f"unknown provider roles: {sorted(unknown)}")
        self.memory = memory
        self._agents = {
            role: agent_type(selected.get(role, provider), temperature=temperature)
            for role, agent_type in self._ROLE_TYPES.items()
        }

    @staticmethod
    def _stage(name: str, plan: AttackPlan) -> PipelineStage:
        digest = hashlib.sha256(plan.to_json().encode("utf-8")).hexdigest()
        return PipelineStage(name=name, plan=plan, plan_sha256=digest)

    def _remember(
        self,
        *,
        context: AgentContext,
        stage: PipelineStage,
        sequence: int,
    ) -> MemoryReceipt | None:
        if self.memory is None:
            return None
        return self.memory.append(
            MemoryEvent(
                attack_id=f"{stage.plan.plan_id}-{stage.name}"[:128],
                campaign_id=context.campaign_id,
                vector=f"agent-{stage.name}"[:128],
                target=context.target[:256],
                phase="planning",
                result="proposed",
                expected=(
                    "strict AttackPlan validated; "
                    f"sha256={stage.plan_sha256}"
                ),
                reason_code="ATTACK_PLAN_VALIDATED",
                blocked=None,
                sequence=sequence,
            )
        )

    def run(
        self,
        context: AgentContext | Mapping[str, Any] | object,
    ) -> PipelineResult:
        ctx = AgentContext.coerce(context)
        stages: list[PipelineStage] = []
        receipts: list[MemoryReceipt] = []

        def add(name: str, plan: AttackPlan) -> AttackPlan:
            stage = self._stage(name, plan)
            stages.append(stage)
            receipt = self._remember(
                context=ctx,
                stage=stage,
                sequence=len(stages),
            )
            if receipt is not None:
                receipts.append(receipt)
            return plan

        recon = add("recon", self._agents["recon"].propose(ctx))
        planned = add(
            "planner",
            self._agents["planner"].propose(ctx.with_plan(recon), recon),
        )
        criticised = add(
            "critic-pre-mutation",
            self._agents["critic"].propose(ctx.with_plan(planned), planned),
        )
        mutated = add(
            "mutator",
            self._agents["mutator"].propose(ctx.with_plan(criticised), criticised),
        )
        checked = add(
            "critic-post-mutation",
            self._agents["critic"].propose(ctx.with_plan(mutated), mutated),
        )
        final = add(
            "minimizer",
            self._agents["minimizer"].propose(ctx.with_plan(checked), checked),
        )
        return PipelineResult(
            plan=final,
            stages=tuple(stages),
            memory_receipts=tuple(receipts),
        )

    def propose(
        self,
        context: AgentContext | Mapping[str, Any] | object,
    ) -> AttackPlan:
        """Implement the coordinator's ``PlanProposer`` protocol."""

        return self.run(context).plan


__all__ = ["AgentPipeline", "PipelineResult", "PipelineStage"]
