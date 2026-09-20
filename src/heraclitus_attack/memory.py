"""Bounded attack-memory sinks backed by the local HeraclitusDB gateway."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from threading import Lock
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable
import unicodedata
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .safety import is_loopback_host


_EVENT_PATH = "/api/v1/agent/red-team/events"
_MAX_RESPONSE_BYTES = 1_048_576
_PROMPT_MEMORY_FIELDS = frozenset(
    {
        "attack_id",
        "campaign_id",
        "vector",
        "target",
        "phase",
        "result",
        "expected",
        "reason_code",
        "blocked",
        "upstream_delta",
        "transport_status",
        "sequence",
        "lsn",
        "timestamp",
    }
)


class MemoryError(RuntimeError):
    """Heraclitus attack-memory operation failed."""


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise MemoryError("HeraclitusDB redirect refused")


def _bounded_text(value: Any, maximum: int, *, field_name: str) -> str:
    text = str(value)
    if not text or len(text) > maximum or any(
        unicodedata.category(char) == "Cc" for char in text
    ):
        raise ValueError(f"{field_name} must contain 1..{maximum} characters")
    return text


def _loopback_origin(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("HeraclitusDB URL must be http(s)")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("HeraclitusDB URL cannot contain credentials/query/fragment")
    if not is_loopback_host(parsed.hostname):
        raise ValueError("HeraclitusDB memory is loopback-only")
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _sanitize_untrusted(
    value: Any,
    *,
    depth: int = 0,
    max_depth: int = 5,
    max_items: int = 64,
    max_string: int = 2_048,
) -> Any:
    if depth >= max_depth:
        return "<TRUNCATED_DEPTH>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:max_string]
    if isinstance(value, list):
        return [
            _sanitize_untrusted(
                item,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                max_string=max_string,
            )
            for item in value[:max_items]
        ]
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in list(value.items())[:max_items]:
            clean[str(key)[:128]] = _sanitize_untrusted(
                item,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                max_string=max_string,
            )
        return clean
    return str(value)[:max_string]


def _memory_prompt_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    """Keep typed outcome metadata; drop arbitrary DB text before any prompt."""

    projected = {
        key: item for key, item in value.items() if key in _PROMPT_MEMORY_FIELDS
    }
    clean = _sanitize_untrusted(projected)
    return clean if isinstance(clean, dict) else {}


@dataclass(frozen=True, slots=True)
class MemoryEvent:
    """Metadata-only event accepted by HeraclitusDB's red-team ledger."""

    attack_id: str
    campaign_id: str
    vector: str
    target: str
    phase: str
    result: str
    expected: str
    reason_code: str | None = None
    blocked: bool | None = None
    upstream_delta: int | None = None
    transport_status: int | None = None
    sequence: int | None = None

    def __post_init__(self) -> None:
        bounds = {
            "attack_id": (self.attack_id, 128),
            "campaign_id": (self.campaign_id, 128),
            "vector": (self.vector, 128),
            "target": (self.target, 256),
            "phase": (self.phase, 64),
            "result": (self.result, 64),
            "expected": (self.expected, 256),
        }
        for name, (value, maximum) in bounds.items():
            _bounded_text(value, maximum, field_name=name)
        if self.reason_code is not None and len(self.reason_code) > 128:
            raise ValueError("reason_code exceeds 128 characters")
        if self.sequence is not None and self.sequence < 0:
            raise ValueError("sequence cannot be negative")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "MemoryEvent":
        allowed = {
            "attack_id",
            "campaign_id",
            "vector",
            "target",
            "phase",
            "result",
            "expected",
            "reason_code",
            "blocked",
            "upstream_delta",
            "transport_status",
            "sequence",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown event fields: {', '.join(sorted(unknown))}")
        return cls(**dict(value))

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "attack_id": self.attack_id,
            "campaign_id": self.campaign_id,
            "vector": self.vector,
            "target": self.target,
            "phase": self.phase,
            "result": self.result,
            "expected": self.expected,
        }
        for name in (
            "reason_code",
            "blocked",
            "upstream_delta",
            "transport_status",
            "sequence",
        ):
            value = getattr(self, name)
            if value is not None:
                result[name] = value
        return result


@dataclass(frozen=True, slots=True)
class MemoryReceipt:
    accepted: bool
    lsn: int | None = None


@dataclass(frozen=True, slots=True)
class UntrustedMemoryRecord:
    """A bounded DB record that must never be interpreted as instructions."""

    payload: Mapping[str, Any]

    def as_prompt_block(self) -> str:
        encoded = json.dumps(self.payload, ensure_ascii=False, sort_keys=True)
        return (
            "<UNTRUSTED_HERACLITUS_MEMORY>\n"
            f"{encoded}\n"
            "</UNTRUSTED_HERACLITUS_MEMORY>"
        )


@runtime_checkable
class MemorySink(Protocol):
    def append(self, event: MemoryEvent) -> MemoryReceipt:
        """Append one immutable event."""

    def recent(
        self,
        *,
        campaign_id: str | None = None,
        limit: int = 50,
    ) -> Sequence[UntrustedMemoryRecord]:
        """Return bounded records explicitly marked as untrusted."""


class InMemoryMemorySink:
    """Thread-safe deterministic sink for tests; never used as durable storage."""

    def __init__(self) -> None:
        self._events: list[MemoryEvent] = []
        self._lock = Lock()

    @property
    def events(self) -> tuple[MemoryEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def append(self, event: MemoryEvent) -> MemoryReceipt:
        if not isinstance(event, MemoryEvent):
            raise TypeError("event must be MemoryEvent")
        with self._lock:
            self._events.append(event)
            lsn = len(self._events)
        return MemoryReceipt(accepted=True, lsn=lsn)

    def recent(
        self,
        *,
        campaign_id: str | None = None,
        limit: int = 50,
    ) -> Sequence[UntrustedMemoryRecord]:
        if not (1 <= limit <= 1_000):
            raise ValueError("limit must be between 1 and 1000")
        with self._lock:
            selected = [
                event
                for event in self._events
                if campaign_id is None or event.campaign_id == campaign_id
            ][-limit:]
        return tuple(
            UntrustedMemoryRecord(_sanitize_untrusted(event.to_dict()))
            for event in reversed(selected)
        )


class HeraclitusMemorySink:
    """Persist metadata in the local append-only red-team event ledger."""

    def __init__(
        self,
        *,
        base_url: str = "http://127.0.0.1:8080",
        bearer_token: str | None = None,
        timeout_seconds: float = 5.0,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> None:
        if not (0.1 <= timeout_seconds <= 30.0):
            raise ValueError("timeout_seconds outside safe range")
        if not (4_096 <= max_response_bytes <= 4_194_304):
            raise ValueError("max_response_bytes outside safe range")
        self.origin = _loopback_origin(base_url)
        self.bearer_token = bearer_token
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self._opener = build_opener(_NoRedirects())

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "heraclitus-attack/2",
        }
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        return headers

    def _json_request(self, request: Request) -> Any:
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_response_bytes + 1)
        except HTTPError as exc:
            raise MemoryError(f"HeraclitusDB returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise MemoryError("local HeraclitusDB is unavailable") from exc
        if len(raw) > self.max_response_bytes:
            raise MemoryError("HeraclitusDB response exceeds byte limit")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MemoryError("HeraclitusDB returned invalid JSON") from exc

    def append(self, event: MemoryEvent) -> MemoryReceipt:
        if not isinstance(event, MemoryEvent):
            raise TypeError("event must be MemoryEvent")
        wire = json.dumps(event.to_dict(), ensure_ascii=False).encode("utf-8")
        request = Request(
            f"{self.origin}{_EVENT_PATH}",
            data=wire,
            headers=self._headers(),
            method="POST",
        )
        response = self._json_request(request)
        if not isinstance(response, dict):
            raise MemoryError("HeraclitusDB append response must be an object")
        lsn = response.get("lsn")
        if isinstance(lsn, bool) or not isinstance(lsn, int) or lsn < 0:
            raise MemoryError("HeraclitusDB append response has no valid LSN")
        return MemoryReceipt(accepted=True, lsn=lsn)

    def recent(
        self,
        *,
        campaign_id: str | None = None,
        limit: int = 50,
    ) -> Sequence[UntrustedMemoryRecord]:
        if not (1 <= limit <= 1_000):
            raise ValueError("limit must be between 1 and 1000")
        params: dict[str, str | int] = {"limit": limit}
        if campaign_id is not None:
            params["campaign"] = _bounded_text(
                campaign_id,
                128,
                field_name="campaign_id",
            )
        request = Request(
            f"{self.origin}{_EVENT_PATH}?{urlencode(params)}",
            headers=self._headers(),
            method="GET",
        )
        response = self._json_request(request)
        if not isinstance(response, dict):
            raise MemoryError("HeraclitusDB query response must be an object")
        events = response.get("events", [])
        if not isinstance(events, list):
            raise MemoryError("HeraclitusDB query response has invalid events")
        return tuple(
            UntrustedMemoryRecord(_memory_prompt_projection(event))
            for event in events[:limit]
            if isinstance(event, dict)
        )


__all__ = [
    "HeraclitusMemorySink",
    "InMemoryMemorySink",
    "MemoryError",
    "MemoryEvent",
    "MemoryReceipt",
    "MemorySink",
    "UntrustedMemoryRecord",
]
