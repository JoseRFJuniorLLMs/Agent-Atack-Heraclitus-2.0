"""Typed, serialisable domain models for the authorised attack lab.

The models deliberately distinguish observations returned by the system under
test from trusted control data.  A database response is always wrapped in
``UntrustedData`` and must never be interpolated into an agent prompt.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping, Sequence, TypeAlias
from uuid import uuid4


JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)


def new_id(prefix: str) -> str:
    """Return a globally unique, log-friendly identifier."""

    clean = re.sub(r"[^a-z0-9-]+", "-", prefix.lower()).strip("-") or "id"
    return f"{clean}-{uuid4().hex}"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class Verdict(str, Enum):
    """Result vocabulary shared by executors, oracles and reports."""

    PASS = "pass"
    FAIL = "fail"
    VULNERABLE = "vulnerable"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class RiskLevel(str, Enum):
    SAFE = "safe"
    ELEVATED = "elevated"
    DESTRUCTIVE = "destructive"


def _json_copy(value: Any, *, label: str) -> JsonValue:
    """Validate JSON compatibility and detach caller-owned mutable values."""

    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
        return json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must contain only finite JSON values") from exc


@dataclass(frozen=True, slots=True)
class AttackStep:
    """One operation in an attack plan.

    ``tool`` names a local, pre-registered adapter.  It never names a Python
    callable, executable, or shell command.
    """

    tool: str
    target: str
    operation: str = "execute"
    arguments: Mapping[str, JsonValue] = field(default_factory=dict)
    timeout_seconds: float | None = None
    destructive: bool = False
    tags: tuple[str, ...] = ()
    step_id: str = field(default_factory=lambda: new_id("step"))

    def __post_init__(self) -> None:
        if not self.tool.strip():
            raise ValueError("AttackStep.tool cannot be empty")
        if not self.target.strip():
            raise ValueError("AttackStep.target cannot be empty")
        if not self.operation.strip():
            raise ValueError("AttackStep.operation cannot be empty")
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("AttackStep.timeout_seconds must be positive")
        args = _json_copy(dict(self.arguments), label="AttackStep.arguments")
        if not isinstance(args, dict):  # pragma: no cover - defensive typing
            raise ValueError("AttackStep.arguments must be an object")
        object.__setattr__(self, "arguments", args)
        object.__setattr__(self, "tags", tuple(str(tag) for tag in self.tags))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AttackStep":
        allowed = {
            "step_id",
            "tool",
            "target",
            "operation",
            "arguments",
            "timeout_seconds",
            "destructive",
            "tags",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown AttackStep fields: {sorted(unknown)}")
        return cls(
            step_id=str(value.get("step_id") or new_id("step")),
            tool=str(value.get("tool", "")),
            target=str(value.get("target", "")),
            operation=str(value.get("operation", "execute")),
            arguments=value.get("arguments") or {},
            timeout_seconds=(
                float(value["timeout_seconds"])
                if value.get("timeout_seconds") is not None
                else None
            ),
            destructive=bool(value.get("destructive", False)),
            tags=tuple(value.get("tags") or ()),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "step_id": self.step_id,
            "tool": self.tool,
            "target": self.target,
            "operation": self.operation,
            "arguments": _json_copy(self.arguments, label="AttackStep.arguments"),
            "timeout_seconds": self.timeout_seconds,
            "destructive": self.destructive,
            "tags": list(self.tags),
        }


@dataclass(frozen=True, slots=True)
class AttackPlan:
    """Strict JSON contract produced by a planner and consumed by the gate."""

    title: str
    hypothesis: str
    steps: tuple[AttackStep, ...]
    oracle_ids: tuple[str, ...]
    plan_id: str = field(default_factory=lambda: new_id("plan"))
    campaign_id: str | None = None
    risk: RiskLevel = RiskLevel.ELEVATED
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.title.strip():
            raise ValueError("AttackPlan.title cannot be empty")
        if not self.hypothesis.strip():
            raise ValueError("AttackPlan.hypothesis cannot be empty")
        steps = tuple(self.steps)
        if not steps:
            raise ValueError("AttackPlan.steps cannot be empty")
        if any(not isinstance(step, AttackStep) for step in steps):
            raise ValueError("AttackPlan.steps must contain AttackStep objects")
        step_ids = [step.step_id for step in steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("AttackPlan step IDs must be unique")
        oracles = tuple(str(item) for item in self.oracle_ids)
        if not oracles:
            raise ValueError("AttackPlan.oracle_ids cannot be empty")
        risk = self.risk if isinstance(self.risk, RiskLevel) else RiskLevel(self.risk)
        metadata = _json_copy(dict(self.metadata), label="AttackPlan.metadata")
        if not isinstance(metadata, dict):  # pragma: no cover
            raise ValueError("AttackPlan.metadata must be an object")
        object.__setattr__(self, "steps", steps)
        object.__setattr__(self, "oracle_ids", oracles)
        object.__setattr__(self, "risk", risk)
        object.__setattr__(self, "metadata", metadata)

    @property
    def destructive(self) -> bool:
        return self.risk is RiskLevel.DESTRUCTIVE or any(
            step.destructive for step in self.steps
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AttackPlan":
        allowed = {
            "plan_id",
            "campaign_id",
            "title",
            "hypothesis",
            "risk",
            "steps",
            "oracle_ids",
            "metadata",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown AttackPlan fields: {sorted(unknown)}")
        raw_steps = value.get("steps")
        if not isinstance(raw_steps, Sequence) or isinstance(raw_steps, (str, bytes)):
            raise ValueError("AttackPlan.steps must be an array")
        raw_oracles = value.get("oracle_ids")
        if not isinstance(raw_oracles, Sequence) or isinstance(
            raw_oracles, (str, bytes)
        ):
            raise ValueError("AttackPlan.oracle_ids must be an array")
        return cls(
            plan_id=str(value.get("plan_id") or new_id("plan")),
            campaign_id=(
                str(value["campaign_id"])
                if value.get("campaign_id") is not None
                else None
            ),
            title=str(value.get("title", "")),
            hypothesis=str(value.get("hypothesis", "")),
            risk=RiskLevel(str(value.get("risk", RiskLevel.ELEVATED.value)).lower()),
            steps=tuple(AttackStep.from_dict(item) for item in raw_steps),
            oracle_ids=tuple(str(item) for item in raw_oracles),
            metadata=value.get("metadata") or {},
        )

    @classmethod
    def from_json(cls, value: str | bytes) -> "AttackPlan":
        try:
            decoded = json.loads(value)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("invalid AttackPlan JSON") from exc
        if not isinstance(decoded, dict):
            raise ValueError("AttackPlan JSON root must be an object")
        return cls.from_dict(decoded)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "plan_id": self.plan_id,
            "campaign_id": self.campaign_id,
            "title": self.title,
            "hypothesis": self.hypothesis,
            "risk": self.risk.value,
            "steps": [step.to_dict() for step in self.steps],
            "oracle_ids": list(self.oracle_ids),
            "metadata": _json_copy(self.metadata, label="AttackPlan.metadata"),
        }

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(
            self.to_dict(), ensure_ascii=False, allow_nan=False, indent=indent
        )


@dataclass(frozen=True, slots=True)
class UntrustedData:
    """Bounded evidence originating outside the trusted control plane."""

    text: str
    content_type: str | None
    byte_length: int
    sha256: str
    truncated: bool = False

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        content_type: str | None = None,
        original_length: int | None = None,
        truncated: bool = False,
    ) -> "UntrustedData":
        length = original_length if original_length is not None else len(data)
        return cls(
            text=data.decode("utf-8", "replace"),
            content_type=content_type,
            byte_length=length,
            sha256=hashlib.sha256(data).hexdigest(),
            truncated=truncated,
        )

    def safe_summary(self, limit: int = 240) -> str:
        """Return inert diagnostics, never text suitable for model feedback."""

        del limit  # Content is intentionally excluded, even when requested.
        suffix = ", truncated" if self.truncated else ""
        return f"untrusted bytes={self.byte_length}, sha256={self.sha256[:16]}{suffix}"


@dataclass(frozen=True, slots=True)
class Observation:
    step_id: str
    tool: str
    target: str
    started_at: str
    duration_ms: float
    ok: bool
    status_code: int | None = None
    error: str | None = None
    untrusted_response: UntrustedData | None = None
    evidence: Mapping[str, JsonValue] = field(default_factory=dict)
    observation_id: str = field(default_factory=lambda: new_id("observation"))

    def __post_init__(self) -> None:
        evidence = _json_copy(dict(self.evidence), label="Observation.evidence")
        object.__setattr__(self, "evidence", evidence)

    def to_dict(self, *, include_untrusted_text: bool = False) -> dict[str, Any]:
        output = asdict(self)
        if self.untrusted_response is not None and not include_untrusted_text:
            output["untrusted_response"]["text"] = "[UNTRUSTED CONTENT OMITTED]"
        return output


@dataclass(frozen=True, slots=True)
class OracleResult:
    oracle_id: str
    verdict: Verdict
    reason: str
    evidence_fingerprint: str | None = None
    details: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        verdict = self.verdict if isinstance(self.verdict, Verdict) else Verdict(self.verdict)
        object.__setattr__(self, "verdict", verdict)
        object.__setattr__(
            self,
            "details",
            _json_copy(dict(self.details), label="OracleResult.details"),
        )


@dataclass(frozen=True, slots=True)
class Finding:
    campaign_id: str
    plan_id: str
    title: str
    verdict: Verdict
    reason: str
    attempts: int
    confirmations: int
    oracle_results: tuple[OracleResult, ...]
    finding_id: str = field(default_factory=lambda: new_id("finding"))
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "verdict",
            self.verdict if isinstance(self.verdict, Verdict) else Verdict(self.verdict),
        )
        object.__setattr__(self, "oracle_results", tuple(self.oracle_results))

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["verdict"] = self.verdict.value
        for item, oracle in zip(value["oracle_results"], self.oracle_results):
            item["verdict"] = oracle.verdict.value
        return value

