"""Shared context, schemas and guards for planning agents."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
from typing import Any, Mapping, Sequence

from ..models import AttackPlan, Observation, RiskLevel
from ..providers import CompletionRequest, LLMProvider, ProviderResponseError


DEFAULT_TOOLS = ("http_request", "mcp_call", "tcp_probe", "upstream_counter")
DEFAULT_ORACLES = (
    "availability",
    "evidence_receipt",
    "http_status",
    "no_sensitive_leak",
    "upstream_zero",
)


class AgentPlanError(ValueError):
    """A model-generated plan violated the planning boundary."""


@dataclass(frozen=True, slots=True)
class AgentContext:
    """Bounded inputs made visible to planner roles.

    Observations are always rendered as untrusted data.  The target and tool
    allowlists are trusted configuration supplied by the coordinator.
    """

    campaign_id: str
    target: str
    objective: str = "test a declared security invariant"
    allowed_tools: tuple[str, ...] = DEFAULT_TOOLS
    allowed_targets: tuple[str, ...] = ()
    allowed_oracles: tuple[str, ...] = DEFAULT_ORACLES
    observations: tuple[Any, ...] = ()
    prior_plans: tuple[AttackPlan, ...] = ()
    max_steps: int = 8
    max_step_timeout_seconds: float = 10.0
    max_risk: RiskLevel = RiskLevel.ELEVATED
    max_untrusted_chars: int = 8_192

    def __post_init__(self) -> None:
        if not self.campaign_id.strip() or len(self.campaign_id) > 128:
            raise ValueError("campaign_id must contain 1..128 characters")
        if not self.target.strip() or len(self.target) > 512:
            raise ValueError("target must contain 1..512 characters")
        if not self.objective.strip() or len(self.objective) > 2_048:
            raise ValueError("objective must contain 1..2048 characters")
        if not (1 <= self.max_steps <= 64):
            raise ValueError("max_steps must be between 1 and 64")
        if not (0.1 <= self.max_step_timeout_seconds <= 120.0):
            raise ValueError("max_step_timeout_seconds outside safe range")
        if not (512 <= self.max_untrusted_chars <= 65_536):
            raise ValueError("max_untrusted_chars outside safe range")
        targets = self.allowed_targets or (self.target,)
        if self.target not in targets:
            raise ValueError("target must be present in allowed_targets")
        if not self.allowed_tools or not self.allowed_oracles:
            raise ValueError("tool and oracle allowlists cannot be empty")
        object.__setattr__(self, "allowed_tools", tuple(self.allowed_tools))
        object.__setattr__(self, "allowed_targets", tuple(targets))
        object.__setattr__(self, "allowed_oracles", tuple(self.allowed_oracles))
        object.__setattr__(self, "observations", tuple(self.observations))
        object.__setattr__(self, "prior_plans", tuple(self.prior_plans))
        object.__setattr__(
            self,
            "max_risk",
            self.max_risk
            if isinstance(self.max_risk, RiskLevel)
            else RiskLevel(str(self.max_risk).lower()),
        )

    @classmethod
    def coerce(cls, value: "AgentContext | Mapping[str, Any] | object") -> "AgentContext":
        if isinstance(value, cls):
            return value
        names = {
            "campaign_id",
            "target",
            "objective",
            "allowed_tools",
            "allowed_targets",
            "allowed_oracles",
            "observations",
            "prior_plans",
            "max_steps",
            "max_step_timeout_seconds",
            "max_risk",
            "max_untrusted_chars",
        }
        if isinstance(value, Mapping):
            raw = {name: value[name] for name in names if name in value}
        else:
            raw = {
                name: getattr(value, name)
                for name in names
                if hasattr(value, name)
            }
        for name in (
            "allowed_tools",
            "allowed_targets",
            "allowed_oracles",
            "observations",
            "prior_plans",
        ):
            if name in raw:
                raw[name] = tuple(raw[name])
        return cls(**raw)

    def with_plan(self, plan: AttackPlan) -> "AgentContext":
        return replace(self, prior_plans=(*self.prior_plans, plan))


def attack_plan_json_schema(max_steps: int = 8) -> dict[str, Any]:
    """Return the exact structural contract accepted from every role."""

    step = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "step_id",
            "tool",
            "target",
            "operation",
            "arguments",
            "timeout_seconds",
            "destructive",
            "tags",
        ],
        "properties": {
            "step_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "tool": {"type": "string", "minLength": 1, "maxLength": 64},
            "target": {"type": "string", "minLength": 1, "maxLength": 512},
            "operation": {"type": "string", "minLength": 1, "maxLength": 64},
            "arguments": {"type": "object"},
            "timeout_seconds": {"type": ["number", "null"], "minimum": 0.1, "maximum": 120.0},
            "destructive": {"type": "boolean"},
            "tags": {
                "type": "array",
                "maxItems": 16,
                "items": {"type": "string", "maxLength": 64},
            },
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "plan_id",
            "campaign_id",
            "title",
            "hypothesis",
            "risk",
            "steps",
            "oracle_ids",
            "metadata",
        ],
        "properties": {
            "plan_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "campaign_id": {"type": ["string", "null"], "maxLength": 128},
            "title": {"type": "string", "minLength": 1, "maxLength": 256},
            "hypothesis": {"type": "string", "minLength": 1, "maxLength": 1_024},
            "risk": {
                "type": "string",
                "enum": ["safe", "elevated", "destructive"],
            },
            "steps": {
                "type": "array",
                "minItems": 1,
                "maxItems": max_steps,
                "items": step,
            },
            "oracle_ids": {
                "type": "array",
                "minItems": 1,
                "maxItems": 8,
                "items": {"type": "string", "minLength": 1, "maxLength": 64},
            },
            "metadata": {"type": "object"},
        },
    }


def _stable_id(role: str, context: AgentContext, parent: str = "") -> str:
    material = f"{role}\0{context.campaign_id}\0{context.target}\0{parent}"
    return f"{role}-{hashlib.sha256(material.encode()).hexdigest()[:20]}"


def _fallback_plan(
    role: str,
    context: AgentContext,
    candidate: AttackPlan | None,
) -> dict[str, Any]:
    if candidate is not None:
        value = candidate.to_dict()
        value["plan_id"] = _stable_id(role, context, candidate.plan_id)
        metadata = dict(value.get("metadata") or {})
        metadata["agent_role"] = role
        metadata["parent_plan_id"] = candidate.plan_id
        value["metadata"] = metadata
        value["campaign_id"] = context.campaign_id
        return value

    tool = "http_request" if "http_request" in context.allowed_tools else sorted(context.allowed_tools)[0]
    arguments: dict[str, Any] = (
        {"method": "GET", "path": "/healthz"}
        if tool == "http_request"
        else {}
    )
    return {
        "plan_id": _stable_id(role, context),
        "campaign_id": context.campaign_id,
        "title": "Bounded loopback reconnaissance",
        "hypothesis": "The declared local target remains available under a read-only probe.",
        "risk": "safe",
        "steps": [
            {
                "step_id": _stable_id("step", context),
                "tool": tool,
                "target": context.target,
                "operation": "observe",
                "arguments": arguments,
                "timeout_seconds": min(5.0, context.max_step_timeout_seconds),
                "destructive": False,
                "tags": ["agentic", "recon", "loopback"],
            }
        ],
        "oracle_ids": [
            "http_status" if tool in {"http_request", "mcp_call"} else context.allowed_oracles[0]
        ],
        "metadata": {
            "agent_role": role,
            **({"expected_statuses": [200]} if tool == "http_request" else {}),
        },
    }


_FORBIDDEN_EXECUTION_KEYS = {
    "argv",
    "bash",
    "cmd",
    "command",
    "executable",
    "powershell",
    "program",
    "python",
    "script",
    "shell",
    "subprocess",
}
_DESTINATION_KEYS = {
    "address",
    "base_url",
    "callback",
    "endpoint",
    "host",
    "hostname",
    "redirect",
    "uri",
    "url",
    "webhook",
}


def _walk_arguments(value: Any, context: AgentContext, path: str = "arguments") -> None:
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key).lower().replace("-", "_")
            if key in _FORBIDDEN_EXECUTION_KEYS:
                raise AgentPlanError(f"{path}.{key}: executable/shell field is forbidden")
            if key in _DESTINATION_KEYS and isinstance(child, str):
                if child not in context.allowed_targets and not child.startswith("/"):
                    raise AgentPlanError(f"{path}.{key}: destination is not allowlisted")
            _walk_arguments(child, context, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_arguments(child, context, f"{path}[{index}]")


def validate_agent_plan(plan: AttackPlan, context: AgentContext) -> None:
    if plan.campaign_id != context.campaign_id:
        raise AgentPlanError("plan campaign_id does not match the active campaign")
    if len(plan.steps) > context.max_steps:
        raise AgentPlanError("plan exceeds the agent step budget")
    levels = {RiskLevel.SAFE: 0, RiskLevel.ELEVATED: 1, RiskLevel.DESTRUCTIVE: 2}
    if levels[plan.risk] > levels[context.max_risk]:
        raise AgentPlanError("plan exceeds the permitted risk level")
    unknown_oracles = set(plan.oracle_ids) - set(context.allowed_oracles)
    if unknown_oracles:
        raise AgentPlanError(f"plan selected unknown oracles: {sorted(unknown_oracles)}")
    for step in plan.steps:
        if step.tool not in context.allowed_tools:
            raise AgentPlanError(f"plan selected a non-allowlisted tool: {step.tool!r}")
        if step.target not in context.allowed_targets:
            raise AgentPlanError("plan selected a non-allowlisted target")
        if step.timeout_seconds and step.timeout_seconds > context.max_step_timeout_seconds:
            raise AgentPlanError("plan step exceeds the timeout budget")
        if step.destructive and context.max_risk is not RiskLevel.DESTRUCTIVE:
            raise AgentPlanError("destructive step is outside this campaign")
        _walk_arguments(step.arguments, context)


class PlanningAgent:
    """Base class for a single role; subclasses provide the role instruction."""

    role = "planner"
    instruction = "Produce the safest useful next plan."

    def __init__(self, provider: LLMProvider, *, temperature: float = 0.0) -> None:
        if not isinstance(provider, LLMProvider):
            raise TypeError("provider must implement LLMProvider")
        self.provider = provider
        self.temperature = temperature

    def propose(
        self,
        context: AgentContext | Mapping[str, Any] | object,
        candidate: AttackPlan | None = None,
    ) -> AttackPlan:
        from .prompts import build_prompts

        ctx = AgentContext.coerce(context)
        system_prompt, user_prompt = build_prompts(
            role=self.role,
            instruction=self.instruction,
            context=ctx,
            candidate=candidate,
        )
        request = CompletionRequest(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=attack_plan_json_schema(ctx.max_steps),
            schema_name=f"{self.role}_attack_plan",
            temperature=self.temperature,
            fallback_json=_fallback_plan(self.role, ctx, candidate),
            metadata={"role": self.role, "campaign_id": ctx.campaign_id},
        )
        raw = self.provider.complete_json(request)
        try:
            plan = AttackPlan.from_dict(raw)
        except (TypeError, ValueError) as exc:
            raise ProviderResponseError("provider returned an invalid AttackPlan") from exc
        validate_agent_plan(plan, ctx)
        return plan


__all__ = [
    "AgentContext",
    "AgentPlanError",
    "DEFAULT_ORACLES",
    "DEFAULT_TOOLS",
    "PlanningAgent",
    "attack_plan_json_schema",
    "validate_agent_plan",
]
