"""Fail-closed validation for plans proposed by humans or language models."""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import ipaddress
import json
import socket
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, unquote, urlsplit

from .config import RuntimeConfig
from .models import AttackPlan, AttackStep, RiskLevel


class SafetyViolation(ValueError):
    """A plan cannot run inside the lab's fixed safety boundary."""


@dataclass(frozen=True, slots=True)
class DestructiveAuthorization:
    """Ephemeral operator approval; deliberately excluded from AttackPlan JSON."""

    snapshot_id: str
    token: str


_READ_ONLY_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_SAFE_SYNTHETIC_MCP_TOOL = "heraclitus_redteam_forbidden_probe"
_SAFE_SYNTHETIC_MARKER = "HERACLITUS_REDTEAM_SYNTHETIC_MARKER"


def effective_http_method(step: AttackStep) -> str | None:
    """Return the actual adapter method, independent of proposer labels."""

    if step.tool not in {"http_request", "mcp_call", "upstream_counter"}:
        return None
    default = "POST" if step.tool == "mcp_call" else "GET"
    return str(step.arguments.get("method", default)).upper()


def _is_safe_synthetic_mcp_post(step: AttackStep) -> bool:
    """Recognise only the two non-mutating POST shapes used by smoke tests."""

    if step.tool != "mcp_call":
        return False
    if str(step.arguments.get("path", "/mcp")) != "/mcp":
        return False
    body = step.arguments.get("body", step.arguments.get("message"))
    if isinstance(body, str):
        try:
            json.loads(body)
        except json.JSONDecodeError:
            # A length-delimited invalid JSON document cannot invoke a method.
            return True
        return False
    if not isinstance(body, Mapping):
        return False
    if set(body) - {"jsonrpc", "id", "method", "params"}:
        return False
    if body.get("jsonrpc") != "2.0" or body.get("method") != "tools/call":
        return False
    params = body.get("params")
    if not isinstance(params, Mapping) or set(params) - {"name", "arguments"}:
        return False
    if params.get("name") != _SAFE_SYNTHETIC_MCP_TOOL:
        return False
    arguments = params.get("arguments")
    return (
        isinstance(arguments, Mapping)
        and arguments.get("marker") == _SAFE_SYNTHETIC_MARKER
    )


def effective_step_requires_authorization(step: AttackStep) -> bool:
    """Classify effects from adapter semantics, never from LLM-provided risk."""

    if step.destructive:
        return True
    method = effective_http_method(step)
    if method is None:
        return False
    carries_payload = any(
        step.arguments.get(name) not in (None, "", {}, [])
        for name in ("body", "message")
    )
    if method in _READ_ONLY_HTTP_METHODS:
        return carries_payload
    if method == "POST" and _is_safe_synthetic_mcp_post(step):
        return False
    return True


def effective_plan_requires_authorization(plan: AttackPlan) -> bool:
    return (
        plan.risk is RiskLevel.DESTRUCTIVE
        or any(effective_step_requires_authorization(step) for step in plan.steps)
    )


def _normalise_host(host: str) -> str:
    return host.strip().strip("[]").rstrip(".").lower()


def is_loopback_host(host: str, *, resolve_localhost: bool = True) -> bool:
    """Return true only when every resolved address is loopback."""

    candidate = _normalise_host(host)
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        pass
    if candidate != "localhost" or not resolve_localhost:
        return False
    try:
        addresses = {
            item[4][0] for item in socket.getaddrinfo(candidate, None, type=socket.SOCK_STREAM)
        }
    except OSError:
        return False
    return bool(addresses) and all(ipaddress.ip_address(item).is_loopback for item in addresses)


def validate_loopback_target(target: str, *, allow_https: bool = True) -> None:
    """Validate an HTTP(S) URL or ``host:port`` TCP target."""

    if not target.startswith(("http://", "https://")):
        host, separator, raw_port = target.rpartition(":")
        if not separator or not host or not raw_port.isdecimal():
            raise SafetyViolation("TCP target must be an HTTP URL or host:port")
        if not is_loopback_host(host):
            raise SafetyViolation("TCP target must resolve exclusively to loopback")
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise SafetyViolation("target port is out of range")
        return

    parsed = urlsplit(target)
    if parsed.scheme:
        allowed_schemes = {"http", "https"} if allow_https else {"http"}
        if parsed.scheme.lower() not in allowed_schemes:
            raise SafetyViolation(f"unsupported target scheme: {parsed.scheme!r}")
        if parsed.username is not None or parsed.password is not None:
            raise SafetyViolation("credentials are forbidden in target URLs")
        if parsed.hostname is None or not is_loopback_host(parsed.hostname):
            raise SafetyViolation("target must resolve exclusively to loopback")
        try:
            port = parsed.port
        except ValueError as exc:
            raise SafetyViolation("target port is invalid") from exc
        if port is not None and not (1 <= port <= 65535):
            raise SafetyViolation("target port is out of range")
        return


def target_host(target: str) -> str:
    """Extract a normalized host from an HTTP origin or host:port target."""

    if target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        if parsed.hostname is None:
            raise SafetyViolation("target has no host")
        return _normalise_host(parsed.hostname)
    host, separator, raw_port = target.rpartition(":")
    if not separator or not host or not raw_port.isdecimal():
        raise SafetyViolation("TCP target must be an HTTP URL or host:port")
    return _normalise_host(host)


def is_remote_target(target: str) -> bool:
    return not is_loopback_host(target_host(target))


def _validate_remote_host(host: str, allowed_remote_hosts: Iterable[str]) -> None:
    """Allow only exact private/link-local IP literals; DNS names are refused."""

    normalized = _normalise_host(host)
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError as exc:
        raise SafetyViolation("remote-lab targets must use an IP literal") from exc
    if not (address.is_private or address.is_link_local):
        raise SafetyViolation("remote-lab target must be a private or link-local address")
    allowed = {_normalise_host(item) for item in allowed_remote_hosts}
    if normalized not in allowed:
        raise SafetyViolation("remote-lab target IP is not explicitly allowlisted")


def validate_authorized_target(
    target: str,
    *,
    allow_https: bool = True,
    allow_remote: bool = False,
    allowed_remote_hosts: Iterable[str] = (),
) -> None:
    """Validate loopback or an explicitly enabled exact private lab host."""

    host = target_host(target)
    if is_loopback_host(host):
        validate_loopback_target(target, allow_https=allow_https)
        return
    if not allow_remote:
        raise SafetyViolation("target must resolve exclusively to loopback")
    # Validate URL/port syntax without resolving attacker-controlled DNS.
    if target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        allowed_schemes = {"http", "https"} if allow_https else {"http"}
        if parsed.scheme.lower() not in allowed_schemes:
            raise SafetyViolation(f"unsupported target scheme: {parsed.scheme!r}")
        if parsed.username is not None or parsed.password is not None:
            raise SafetyViolation("credentials are forbidden in target URLs")
        try:
            port = parsed.port
        except ValueError as exc:
            raise SafetyViolation("target port is invalid") from exc
        if port is not None and not 1 <= port <= 65535:
            raise SafetyViolation("target port is out of range")
    else:
        _host, _separator, raw_port = target.rpartition(":")
        if not raw_port.isdecimal() or not 1 <= int(raw_port) <= 65535:
            raise SafetyViolation("target port is out of range")
    _validate_remote_host(host, allowed_remote_hosts)


def canonical_target(target: str) -> str:
    """Canonical origin used by the exact campaign target allowlist."""

    if target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        if parsed.hostname is None:
            raise SafetyViolation("target has no host")
        scheme = parsed.scheme.lower()
        host = _normalise_host(parsed.hostname)
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port or (443 if scheme == "https" else 80)
        return f"{scheme}://{host}:{port}"
    host, _, raw_port = target.rpartition(":")
    host = _normalise_host(host)
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{int(raw_port)}"

def _nested_targets(value: Any, parent_key: str = "") -> Iterable[str]:
    """Find URL/host-shaped arguments which could otherwise smuggle SSRF."""

    target_keys = {
        "url",
        "uri",
        "target",
        "endpoint",
        "base_url",
        "dest",
        "destination",
        "fetch",
        "host",
        "link",
        "next",
        "address",
        "proxy",
        "redirect",
        "return_to",
        "source",
        "callback",
        "webhook",
    }
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalised = str(key).lower().replace("-", "_")
            if normalised in target_keys and isinstance(child, str):
                yield child
            yield from _nested_targets(child, normalised)
    elif isinstance(value, list):
        for child in value:
            yield from _nested_targets(child, parent_key)


class SafetyGate:
    """Validate plans before any I/O occurs."""

    def __init__(
        self,
        config: RuntimeConfig,
        *,
        target_allowlist: Iterable[str] | None = None,
    ) -> None:
        self.config = config
        configured = (
            config.safety.allowed_targets
            if target_allowlist is None
            else frozenset(target_allowlist)
        )
        canonical: set[str] = set()
        for target in configured:
            validate_authorized_target(
                target,
                allow_https=self.config.safety.allow_https,
                allow_remote=self.config.safety.allow_remote_targets,
                allowed_remote_hosts=self.config.safety.allowed_remote_hosts,
            )
            canonical.add(canonical_target(target))
        self.allowed_targets = frozenset(canonical)

    def _validate_target_allowed(self, target: str) -> None:
        if canonical_target(target) not in self.allowed_targets:
            raise SafetyViolation(
                "target is not in the exact campaign target allowlist"
            )

    def validate_plan(
        self,
        plan: AttackPlan,
        authorization: DestructiveAuthorization | None = None,
    ) -> None:
        budget = self.config.budgets
        if len(plan.steps) > budget.max_steps_per_plan:
            raise SafetyViolation(
                f"plan has {len(plan.steps)} steps; limit is {budget.max_steps_per_plan}"
            )
        for step in plan.steps:
            self.validate_step(step)
        if effective_plan_requires_authorization(plan):
            self.validate_destructive_authorization(authorization)

    def validate_step(self, step: AttackStep) -> None:
        if step.tool not in self.config.safety.allowed_tools:
            raise SafetyViolation(f"tool adapter is not allowlisted: {step.tool!r}")
        validate_authorized_target(
            step.target,
            allow_https=self.config.safety.allow_https,
            allow_remote=self.config.safety.allow_remote_targets,
            allowed_remote_hosts=self.config.safety.allowed_remote_hosts,
        )
        if is_remote_target(step.target) and not self.config.expected_remote_lab_token():
            raise SafetyViolation(
                f"remote-lab target requires {self.config.safety.remote_lab_token_env}"
            )
        self._validate_target_allowed(step.target)
        timeout = step.timeout_seconds or self.config.budgets.step_timeout_seconds
        if timeout > self.config.budgets.step_timeout_seconds:
            raise SafetyViolation("step timeout exceeds configured budget")
        try:
            payload = json.dumps(step.arguments, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise SafetyViolation("step arguments are not strict JSON") from exc
        if len(payload) > self.config.budgets.max_payload_bytes:
            raise SafetyViolation("step arguments exceed payload budget")

        sensitive_names = {
            "authorization",
            "proxy_authorization",
            "cookie",
            "set_cookie",
            "api_key",
            "apikey",
            "token",
            "password",
            "secret",
            "client_secret",
            "credential",
            "credentials",
        }

        def reject_credentials(value: Any) -> None:
            if isinstance(value, Mapping):
                for key, child in value.items():
                    name = str(key).lower().replace("-", "_")
                    if name in sensitive_names or name.endswith("_token"):
                        raise SafetyViolation(
                            "credentials and secrets are forbidden in attack plans"
                        )
                    reject_credentials(child)
            elif isinstance(value, list):
                for child in value:
                    reject_credentials(child)

        reject_credentials(step.arguments)

        if step.tool in {"http_request", "mcp_call", "upstream_counter"}:
            method = effective_http_method(step) or "GET"
            if method not in self.config.safety.allowed_http_methods:
                raise SafetyViolation(f"HTTP method is not allowlisted: {method!r}")
            path = str(step.arguments.get("path", "/"))
            parsed_path = urlsplit(path)
            if parsed_path.scheme or parsed_path.netloc or not path.startswith("/"):
                raise SafetyViolation("HTTP path must be relative to the loopback target")
            decoded_path = unquote(parsed_path.path).casefold()
            if "http://" in decoded_path or "https://" in decoded_path:
                raise SafetyViolation(
                    "embedded URL is forbidden in an HTTP path segment"
                )
            try:
                query_items = parse_qsl(
                    parsed_path.query,
                    keep_blank_values=True,
                    max_num_fields=64,
                )
            except ValueError as exc:
                raise SafetyViolation("HTTP query exceeds safety limits") from exc
            query_arguments = {key: value for key, value in query_items}
            query_destinations: list[str] = []
            for _key, value in query_items:
                decoded = unquote(value).strip()
                if decoded.startswith(("http://", "https://")):
                    query_destinations.append(decoded)

        # An LLM cannot bypass the outer target restriction through arguments.
        nested_values = list(_nested_targets(step.arguments))
        if step.tool in {"http_request", "mcp_call", "upstream_counter"}:
            nested_values.extend(_nested_targets(query_arguments))
            nested_values.extend(query_destinations)
        for nested in nested_values:
            if nested.startswith(("http://", "https://")):
                validate_authorized_target(
                    nested,
                    allow_https=self.config.safety.allow_https,
                    allow_remote=self.config.safety.allow_remote_targets,
                    allowed_remote_hosts=self.config.safety.allowed_remote_hosts,
                )
                self._validate_target_allowed(nested)
            elif nested.startswith("/"):
                continue
            elif ":" in nested:
                validate_authorized_target(
                    nested,
                    allow_https=self.config.safety.allow_https,
                    allow_remote=self.config.safety.allow_remote_targets,
                    allowed_remote_hosts=self.config.safety.allowed_remote_hosts,
                )
                self._validate_target_allowed(nested)
            else:
                # A bare host has no port, so it cannot satisfy the exact
                # campaign allowlist and could acquire an unsafe default later
                # inside a downstream tool.
                raise SafetyViolation(
                    "nested destination must be an explicit allowlisted origin"
                )

    def validate_destructive_authorization(
        self, authorization: DestructiveAuthorization | None
    ) -> None:
        if authorization is None:
            raise SafetyViolation(
                "destructive plan requires explicit snapshot and operator token"
            )
        if self.config.safety.require_snapshot_for_destructive and not authorization.snapshot_id.strip():
            raise SafetyViolation("destructive plan requires a non-empty snapshot ID")
        expected = self.config.expected_destructive_token()
        if not expected:
            raise SafetyViolation("destructive token is not configured in the environment")
        if not authorization.token or not hmac.compare_digest(
            authorization.token.encode("utf-8"), expected.encode("utf-8")
        ):
            raise SafetyViolation("destructive token is invalid")
