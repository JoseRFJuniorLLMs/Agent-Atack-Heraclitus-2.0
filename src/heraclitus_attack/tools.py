"""Small, fixed set of allowlisted I/O adapters.

There is intentionally no generic command, import, Python, filesystem, or
subprocess adapter.  Tool names in an LLM-produced plan select only one of the
objects in :func:`default_tool_registry`.
"""

from __future__ import annotations

from dataclasses import dataclass
import http.client
import json
import socket
import ssl
import time
from typing import Mapping, Protocol
from urllib.parse import urlsplit

from .models import AttackStep, JsonValue, Observation, UntrustedData, utc_now


class ToolAdapter(Protocol):
    def execute(
        self,
        step: AttackStep,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        user_agent: str,
    ) -> Observation: ...


def _safe_error(exc: BaseException) -> str:
    # Exception messages can contain reflected hostile input.  Keep only type.
    return f"{type(exc).__name__} during loopback tool execution"


def _body_bytes(value: JsonValue | None) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value.encode("utf-8")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def _headers(value: object, user_agent: str) -> dict[str, str]:
    output = {"User-Agent": user_agent, "Accept": "application/json"}
    if value is None:
        return output
    if not isinstance(value, Mapping):
        raise ValueError("headers must be an object")
    if len(value) > 64:
        raise ValueError("too many HTTP headers")
    forbidden = {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
    }
    for raw_name, raw_value in value.items():
        name, item = str(raw_name), str(raw_value)
        if name.lower() in forbidden:
            raise ValueError(f"caller cannot override {name!r}")
        if not name or len(name) > 128 or len(item) > 8192:
            raise ValueError("HTTP header exceeds limit")
        if "\r" in name or "\n" in name or "\r" in item or "\n" in item:
            raise ValueError("newline in HTTP header")
        output[name] = item
    return output


def _merge_trusted_headers(
    output: dict[str, str], trusted: Mapping[str, str]
) -> dict[str, str]:
    """Merge control-plane credentials after untrusted headers were rejected.

    This function is deliberately not reachable through ``AttackStep.arguments``.
    Only the credential adapter calls the trusted execution entry point.
    """

    allowed = {"authorization", "x-api-key"}
    for raw_name, raw_value in trusted.items():
        name, item = str(raw_name), str(raw_value)
        if name.lower() not in allowed:
            raise ValueError(f"unsupported trusted header: {name!r}")
        if not name or len(name) > 128 or len(item) > 8192:
            raise ValueError("trusted HTTP header exceeds limit")
        if "\r" in name or "\n" in name or "\r" in item or "\n" in item:
            raise ValueError("newline in trusted HTTP header")
        output[name] = item
    return output


@dataclass(frozen=True, slots=True)
class HttpRequestTool:
    """Bounded HTTP client with redirects deliberately unsupported."""

    default_method: str = "GET"

    def execute_with_trusted_headers(
        self,
        step: AttackStep,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        user_agent: str,
        trusted_headers: Mapping[str, str],
    ) -> Observation:
        return self._execute(
            step,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            user_agent=user_agent,
            trusted_headers=trusted_headers,
        )

    def execute(
        self,
        step: AttackStep,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        user_agent: str,
    ) -> Observation:
        return self._execute(
            step,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            user_agent=user_agent,
            trusted_headers={},
        )

    def _execute(
        self,
        step: AttackStep,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        user_agent: str,
        trusted_headers: Mapping[str, str],
    ) -> Observation:
        started_at = utc_now()
        started = time.monotonic()
        connection: http.client.HTTPConnection | None = None
        try:
            parsed = urlsplit(step.target)
            method = str(step.arguments.get("method", self.default_method)).upper()
            suffix = str(step.arguments.get("path", "/"))
            path = f"{parsed.path.rstrip('/')}{suffix}" or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            body = _body_bytes(step.arguments.get("body"))
            headers = _headers(step.arguments.get("headers"), user_agent)
            _merge_trusted_headers(headers, trusted_headers)
            if body is not None:
                headers.setdefault("Content-Type", "application/json")
                headers["Content-Length"] = str(len(body))

            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if parsed.scheme == "https":
                # Verification stays enabled even on loopback.  Test instances
                # can use a locally trusted CA rather than an insecure bypass.
                connection = http.client.HTTPSConnection(
                    parsed.hostname,
                    port,
                    timeout=timeout_seconds,
                    context=ssl.create_default_context(),
                )
            else:
                connection = http.client.HTTPConnection(
                    parsed.hostname, port, timeout=timeout_seconds
                )
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(max_response_bytes + 1)
            truncated = len(raw) > max_response_bytes
            kept = raw[:max_response_bytes]
            data = UntrustedData.from_bytes(
                kept,
                content_type=response.getheader("Content-Type"),
                original_length=len(raw),
                truncated=truncated,
            )
            return Observation(
                step_id=step.step_id,
                tool=step.tool,
                target=step.target,
                started_at=started_at,
                duration_ms=(time.monotonic() - started) * 1000,
                ok=100 <= response.status < 600,
                status_code=response.status,
                untrusted_response=data,
                evidence={
                    "method": method,
                    "response_bytes_observed": len(raw),
                    "response_truncated": truncated,
                },
            )
        except (OSError, ValueError, http.client.HTTPException) as exc:
            return Observation(
                step_id=step.step_id,
                tool=step.tool,
                target=step.target,
                started_at=started_at,
                duration_ms=(time.monotonic() - started) * 1000,
                ok=False,
                error=_safe_error(exc),
            )
        finally:
            if connection is not None:
                connection.close()


@dataclass(frozen=True, slots=True)
class McpCallTool:
    """Send a JSON-RPC message to the target gateway; execute nothing locally."""

    def execute_with_trusted_headers(
        self,
        step: AttackStep,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        user_agent: str,
        trusted_headers: Mapping[str, str],
    ) -> Observation:
        return self._execute(
            step,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            user_agent=user_agent,
            trusted_headers=trusted_headers,
        )

    def execute(
        self,
        step: AttackStep,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        user_agent: str,
    ) -> Observation:
        return self._execute(
            step,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            user_agent=user_agent,
            trusted_headers={},
        )

    def _execute(
        self,
        step: AttackStep,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        user_agent: str,
        trusted_headers: Mapping[str, str],
    ) -> Observation:
        arguments = dict(step.arguments)
        arguments.setdefault("method", "POST")
        arguments.setdefault("path", "/mcp")
        if "body" not in arguments:
            arguments["body"] = arguments.pop("message", {})
        headers = dict(arguments.get("headers") or {})
        headers.setdefault("Content-Type", "application/json")
        arguments["headers"] = headers
        delegated = AttackStep(
            step_id=step.step_id,
            tool=step.tool,
            target=step.target,
            operation=step.operation,
            arguments=arguments,
            timeout_seconds=step.timeout_seconds,
            destructive=step.destructive,
            tags=step.tags,
        )
        return HttpRequestTool(default_method="POST").execute_with_trusted_headers(
            delegated,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            user_agent=user_agent,
            trusted_headers=trusted_headers,
        )


@dataclass(frozen=True, slots=True)
class TcpProbeTool:
    """Measure reachability of a loopback listener without sending payloads."""

    def execute(
        self,
        step: AttackStep,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        user_agent: str,
    ) -> Observation:
        del max_response_bytes, user_agent
        started_at = utc_now()
        started = time.monotonic()
        host, _, raw_port = step.target.rpartition(":")
        try:
            with socket.create_connection(
                (host.strip("[]"), int(raw_port)), timeout=timeout_seconds
            ):
                pass
            return Observation(
                step_id=step.step_id,
                tool=step.tool,
                target=step.target,
                started_at=started_at,
                duration_ms=(time.monotonic() - started) * 1000,
                ok=True,
                evidence={"reachable": True},
            )
        except (OSError, ValueError) as exc:
            return Observation(
                step_id=step.step_id,
                tool=step.tool,
                target=step.target,
                started_at=started_at,
                duration_ms=(time.monotonic() - started) * 1000,
                ok=False,
                error=_safe_error(exc),
                evidence={"reachable": False},
            )


@dataclass(frozen=True, slots=True)
class UpstreamCounterTool:
    """Read a synthetic side-effect counter as typed oracle evidence."""

    def execute(
        self,
        step: AttackStep,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        user_agent: str,
    ) -> Observation:
        arguments = dict(step.arguments)
        arguments.setdefault("method", "GET")
        arguments.setdefault("path", "/hits")
        delegated = AttackStep(
            step_id=step.step_id,
            tool=step.tool,
            target=step.target,
            operation=step.operation,
            arguments=arguments,
            timeout_seconds=step.timeout_seconds,
            destructive=step.destructive,
            tags=step.tags,
        )
        observed = HttpRequestTool().execute(
            delegated,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            user_agent=user_agent,
        )
        counter: int | None = None
        if observed.untrusted_response is not None:
            try:
                decoded = json.loads(observed.untrusted_response.text)
                value = decoded.get("hits") if isinstance(decoded, dict) else None
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    counter = value
            except (json.JSONDecodeError, AttributeError):
                pass
        evidence = dict(observed.evidence)
        evidence["counter"] = counter
        return Observation(
            step_id=observed.step_id,
            tool=observed.tool,
            target=observed.target,
            started_at=observed.started_at,
            duration_ms=observed.duration_ms,
            ok=observed.ok and counter is not None,
            status_code=observed.status_code,
            error=observed.error if counter is not None else "counter unavailable",
            untrusted_response=observed.untrusted_response,
            evidence=evidence,
            observation_id=observed.observation_id,
        )


def default_tool_registry() -> dict[str, ToolAdapter]:
    return {
        "http_request": HttpRequestTool(),
        "mcp_call": McpCallTool(),
        "tcp_probe": TcpProbeTool(),
        "upstream_counter": UpstreamCounterTool(),
    }
