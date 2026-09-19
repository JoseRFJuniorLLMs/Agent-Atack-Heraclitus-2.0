"""Application settings layered on top of the execution safety config."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
import json
from pathlib import Path
from typing import Any, Mapping

from .config import RuntimeConfig
from .safety import validate_loopback_target


@dataclass(frozen=True, slots=True)
class TargetSettings:
    core_rest: str = "http://127.0.0.1:7475"
    core_grpc: str = "127.0.0.1:7474"
    agent_api: str = "http://127.0.0.1:8080"
    mcp_gateway: str = "http://127.0.0.1:8787"
    otlp: str = "http://127.0.0.1:4318"
    upstream: str = "http://127.0.0.1:19000"

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            validate_loopback_target(value)
            if name != "core_grpc" and not value.startswith(("http://", "https://")):
                raise ValueError(f"targets.{name} must be an HTTP(S) URL")


@dataclass(frozen=True, slots=True)
class ProviderSettings:
    kind: str = "mock"
    base_url: str = "http://127.0.0.1:11434/v1"
    model: str = "deterministic-safe-planner"
    api_key_env: str = "HERACLITUS_LLM_API_KEY"
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        normalized = self.kind.casefold()
        if normalized not in {"mock", "openai-compatible"}:
            raise ValueError("provider.kind must be mock or openai-compatible")
        object.__setattr__(self, "kind", normalized)
        if not self.model.strip():
            raise ValueError("provider.model cannot be empty")
        if not self.api_key_env.replace("_", "").isalnum():
            raise ValueError("provider.api_key_env must be an environment variable name")
        if not 0.1 <= self.timeout_seconds <= 120:
            raise ValueError("provider.timeout_seconds outside safe range")


@dataclass(frozen=True, slots=True)
class CampaignSettings:
    profile: str = "smoke"
    interval_seconds: float = 300.0
    plans_per_cycle: int = 4
    max_cycles: int | None = None
    agentic: bool = True
    persist_evidence: bool = True
    report_dir: str = "reports"

    def __post_init__(self) -> None:
        if self.profile not in {"smoke", "full", "destructive"}:
            raise ValueError("campaign.profile must be smoke, full or destructive")
        if self.interval_seconds < 1:
            raise ValueError("campaign.interval_seconds must be at least 1")
        if self.plans_per_cycle <= 0:
            raise ValueError("campaign.plans_per_cycle must be positive")
        if self.max_cycles is not None and self.max_cycles <= 0:
            raise ValueError("campaign.max_cycles must be positive when set")
        if not self.report_dir.strip():
            raise ValueError("campaign.report_dir cannot be empty")


@dataclass(frozen=True, slots=True)
class LabSettings:
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    targets: TargetSettings = field(default_factory=TargetSettings)
    provider: ProviderSettings = field(default_factory=ProviderSettings)
    campaign: CampaignSettings = field(default_factory=CampaignSettings)

    def __post_init__(self) -> None:
        configured_targets = frozenset(asdict(self.targets).values())
        explicit = self.runtime.safety.allowed_targets
        if explicit and not explicit.issubset(configured_targets):
            raise ValueError(
                "runtime.safety.allowed_targets must be declared in targets"
            )
        if not explicit:
            safety = replace(
                self.runtime.safety,
                allowed_targets=configured_targets,
            )
            object.__setattr__(self, "runtime", replace(self.runtime, safety=safety))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LabSettings":
        unknown = set(value) - {"runtime", "targets", "provider", "campaign"}
        if unknown:
            raise ValueError(f"unknown LabSettings fields: {sorted(unknown)}")
        return cls(
            runtime=RuntimeConfig.from_dict(value.get("runtime") or {}),
            targets=TargetSettings(**dict(value.get("targets") or {})),
            provider=ProviderSettings(**dict(value.get("provider") or {})),
            campaign=CampaignSettings(**dict(value.get("campaign") or {})),
        )

    @classmethod
    def from_json(cls, value: str | bytes) -> "LabSettings":
        decoded = json.loads(value)
        if not isinstance(decoded, dict):
            raise ValueError("configuration root must be an object")
        return cls.from_dict(decoded)

    @classmethod
    def load(cls, path: str | Path | None) -> "LabSettings":
        if path is None:
            return cls()
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime": {
                "budgets": asdict(self.runtime.budgets),
                "safety": {
                    "allowed_tools": sorted(self.runtime.safety.allowed_tools),
                    "allowed_http_methods": sorted(
                        self.runtime.safety.allowed_http_methods
                    ),
                    "allowed_targets": sorted(self.runtime.safety.allowed_targets),
                    "allow_https": self.runtime.safety.allow_https,
                    "destructive_token_env": self.runtime.safety.destructive_token_env,
                    "require_snapshot_for_destructive": self.runtime.safety.require_snapshot_for_destructive,
                },
                "user_agent": self.runtime.user_agent,
            },
            "targets": asdict(self.targets),
            "provider": asdict(self.provider),
            "campaign": asdict(self.campaign),
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
