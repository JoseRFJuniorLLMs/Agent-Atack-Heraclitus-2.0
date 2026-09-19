"""Configuration with conservative, bounded defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class BudgetConfig:
    max_plans: int = 8
    max_steps_per_plan: int = 12
    max_requests_per_plan: int = 48
    max_concurrency: int = 4
    max_payload_bytes: int = 64 * 1024
    max_response_bytes: int = 256 * 1024
    step_timeout_seconds: float = 8.0
    plan_timeout_seconds: float = 90.0
    campaign_timeout_seconds: float = 600.0
    confirmation_runs: int = 3

    def __post_init__(self) -> None:
        for name in (
            "max_plans",
            "max_steps_per_plan",
            "max_requests_per_plan",
            "max_concurrency",
            "max_payload_bytes",
            "max_response_bytes",
            "confirmation_runs",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        for name in (
            "step_timeout_seconds",
            "plan_timeout_seconds",
            "campaign_timeout_seconds",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.step_timeout_seconds > self.plan_timeout_seconds:
            raise ValueError("step timeout cannot exceed plan timeout")
        if self.plan_timeout_seconds > self.campaign_timeout_seconds:
            raise ValueError("plan timeout cannot exceed campaign timeout")


@dataclass(frozen=True, slots=True)
class SafetyConfig:
    allowed_tools: frozenset[str] = frozenset(
        {"http_request", "mcp_call", "tcp_probe", "upstream_counter"}
    )
    allowed_http_methods: frozenset[str] = frozenset(
        {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
    )
    # Empty is intentionally deny-all.  A campaign must name its exact lab
    # listeners, preventing an LLM from turning loopback access into a port scan.
    allowed_targets: frozenset[str] = frozenset()
    allow_https: bool = True
    destructive_token_env: str = "HERACLITUS_ATTACK_DESTRUCTIVE_TOKEN"
    require_snapshot_for_destructive: bool = True

    def __post_init__(self) -> None:
        if not self.allowed_tools:
            raise ValueError("allowed_tools cannot be empty")
        if any(not name or not name.replace("_", "").isalnum() for name in self.allowed_tools):
            raise ValueError("allowed_tools contains an invalid adapter name")


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    budgets: BudgetConfig = field(default_factory=BudgetConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    user_agent: str = "Agent-Atack-Heraclitus/2.0"

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RuntimeConfig":
        unknown = set(value) - {"budgets", "safety", "user_agent"}
        if unknown:
            raise ValueError(f"unknown RuntimeConfig fields: {sorted(unknown)}")
        raw_budgets = dict(value.get("budgets") or {})
        raw_safety = dict(value.get("safety") or {})
        if "allowed_tools" in raw_safety:
            raw_safety["allowed_tools"] = frozenset(raw_safety["allowed_tools"])
        if "allowed_http_methods" in raw_safety:
            raw_safety["allowed_http_methods"] = frozenset(
                str(method).upper() for method in raw_safety["allowed_http_methods"]
            )
        if "allowed_targets" in raw_safety:
            raw_safety["allowed_targets"] = frozenset(raw_safety["allowed_targets"])
        return cls(
            budgets=BudgetConfig(**raw_budgets),
            safety=SafetyConfig(**raw_safety),
            user_agent=str(
                value.get("user_agent", "Agent-Atack-Heraclitus/2.0")
            ),
        )

    @classmethod
    def from_json(cls, value: str | bytes) -> "RuntimeConfig":
        decoded = json.loads(value)
        if not isinstance(decoded, dict):
            raise ValueError("configuration root must be an object")
        return cls.from_dict(decoded)

    @classmethod
    def load(cls, path: str | Path) -> "RuntimeConfig":
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    def expected_destructive_token(self) -> str | None:
        """Read the operator secret at use time; never serialise it into plans."""

        token = os.environ.get(self.safety.destructive_token_env, "").strip()
        return token or None


# Friendly alias for callers that prefer an application-level name.
AppConfig = RuntimeConfig
