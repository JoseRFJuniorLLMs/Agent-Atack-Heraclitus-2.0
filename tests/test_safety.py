import socket

import pytest

from heraclitus_attack.config import BudgetConfig, RuntimeConfig, SafetyConfig
from heraclitus_attack.models import AttackPlan, AttackStep, RiskLevel
from heraclitus_attack.safety import (
    DestructiveAuthorization,
    SafetyGate,
    SafetyViolation,
    effective_plan_requires_authorization,
    effective_step_requires_authorization,
    is_loopback_host,
    is_remote_target,
    validate_authorized_target,
    validate_loopback_target,
)


def step(**overrides):
    values = {
        "tool": "http_request",
        "target": "http://127.0.0.1:7475",
        "arguments": {"method": "GET", "path": "/health"},
    }
    values.update(overrides)
    return AttackStep(**values)


def plan(one_step=None, **overrides):
    values = {
        "title": "safe probe",
        "hypothesis": "the boundary remains closed",
        "steps": (one_step or step(),),
        "oracle_ids": ("status",),
        "risk": RiskLevel.SAFE,
    }
    values.update(overrides)
    return AttackPlan(**values)


def runtime(*, budgets=None, safety=None):
    return RuntimeConfig(
        budgets=budgets or BudgetConfig(),
        safety=safety
        or SafetyConfig(allowed_targets=frozenset({"http://127.0.0.1:7475"})),
    )


@pytest.mark.parametrize("host", ["127.0.0.1", "127.99.4.2", "::1", "[::1]"])
def test_literal_loopback_hosts_are_accepted(host):
    assert is_loopback_host(host)


@pytest.mark.parametrize("host", ["8.8.8.8", "10.0.0.1", "example.com", ""])
def test_remote_or_unknown_hosts_are_rejected(host):
    assert not is_loopback_host(host)


def test_localhost_requires_every_dns_result_to_be_loopback(monkeypatch):
    loopback = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: loopback)
    assert is_loopback_host("localhost")
    mixed = loopback + [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: mixed)
    assert not is_loopback_host("localhost")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: (_ for _ in ()).throw(OSError()))
    assert not is_loopback_host("localhost")


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1:7475",
        "https://[::1]:8443/path",
        "127.0.0.1:7474",
        "[::1]:7474",
    ],
)
def test_loopback_targets_are_accepted(target):
    validate_loopback_target(target)


@pytest.mark.parametrize(
    "target",
    [
        "http://example.com:7475",
        "ftp://127.0.0.1/file",
        "http://user:secret@127.0.0.1/",
        "127.0.0.1",
        "127.0.0.1:0",
        "127.0.0.1:99999",
        "not-a-target",
    ],
)
def test_unsafe_targets_are_rejected(target):
    with pytest.raises(SafetyViolation):
        validate_loopback_target(target)


def test_https_can_be_disabled():
    with pytest.raises(SafetyViolation, match="scheme"):
        validate_loopback_target("https://127.0.0.1", allow_https=False)


def test_remote_lab_accepts_only_exact_private_ip_literals():
    validate_authorized_target(
        "http://192.168.56.20:7475",
        allow_remote=True,
        allowed_remote_hosts={"192.168.56.20"},
    )
    assert is_remote_target("192.168.56.20:7474")
    with pytest.raises(SafetyViolation, match="IP literal"):
        validate_authorized_target(
            "http://db-lab.local:7475",
            allow_remote=True,
            allowed_remote_hosts={"db-lab.local"},
        )
    with pytest.raises(SafetyViolation, match="private or link-local"):
        validate_authorized_target(
            "https://8.8.8.8:7475",
            allow_remote=True,
            allowed_remote_hosts={"8.8.8.8"},
        )
    with pytest.raises(SafetyViolation, match="explicitly allowlisted"):
        validate_authorized_target(
            "http://192.168.56.21:7475",
            allow_remote=True,
            allowed_remote_hosts={"192.168.56.20"},
        )


def test_remote_gate_requires_ephemeral_operator_token(monkeypatch):
    target = "http://192.168.56.20:7475"
    config = RuntimeConfig(
        safety=SafetyConfig(
            allowed_targets=frozenset({target}),
            allow_remote_targets=True,
            allowed_remote_hosts=frozenset({"192.168.56.20"}),
        )
    )
    remote_step = step(target=target)
    monkeypatch.delenv(config.safety.remote_lab_token_env, raising=False)
    with pytest.raises(SafetyViolation, match="HERACLITUS_REMOTE_LAB_TOKEN"):
        SafetyGate(config).validate_step(remote_step)
    monkeypatch.setenv(config.safety.remote_lab_token_env, "one-window-only")
    SafetyGate(config).validate_step(remote_step)


def test_gate_accepts_a_bounded_plan():
    SafetyGate(runtime()).validate_plan(plan())


def test_empty_target_allowlist_is_deny_all_and_other_local_ports_are_rejected():
    with pytest.raises(SafetyViolation, match="target allowlist"):
        SafetyGate(RuntimeConfig()).validate_plan(plan())
    gate = SafetyGate(runtime())
    with pytest.raises(SafetyViolation, match="target allowlist"):
        gate.validate_step(step(target="http://127.0.0.1:9999"))


def test_gate_rejects_too_many_steps():
    config = runtime(budgets=BudgetConfig(max_steps_per_plan=1))
    with pytest.raises(SafetyViolation, match="limit"):
        SafetyGate(config).validate_plan(plan(steps=(step(), step())))


def test_gate_rejects_unknown_tool_remote_target_and_long_timeout():
    gate = SafetyGate(runtime())
    with pytest.raises(SafetyViolation, match="allowlisted"):
        gate.validate_step(step(tool="shell"))
    with pytest.raises(SafetyViolation, match="loopback"):
        gate.validate_step(step(target="http://192.0.2.10"))
    with pytest.raises(SafetyViolation, match="timeout"):
        gate.validate_step(step(timeout_seconds=60))


def test_gate_rejects_payload_method_and_absolute_http_path():
    config = runtime(budgets=BudgetConfig(max_payload_bytes=32))
    gate = SafetyGate(config)
    with pytest.raises(SafetyViolation, match="payload"):
        gate.validate_step(step(arguments={"body": "x" * 100}))

    gate = SafetyGate(runtime())
    with pytest.raises(SafetyViolation, match="method"):
        gate.validate_step(step(arguments={"method": "TRACE", "path": "/"}))
    with pytest.raises(SafetyViolation, match="relative"):
        gate.validate_step(step(arguments={"method": "GET", "path": "http://127.0.0.1/other"}))


def test_get_with_body_is_not_treated_as_read_only(monkeypatch):
    config = runtime()
    candidate = plan(
        step(arguments={"method": "GET", "path": "/search", "body": {"x": 1}})
    )

    assert effective_plan_requires_authorization(candidate)
    with pytest.raises(SafetyViolation, match="explicit snapshot"):
        SafetyGate(config).validate_plan(candidate)
    monkeypatch.setenv(config.safety.destructive_token_env, "token")
    SafetyGate(config).validate_plan(
        candidate, DestructiveAuthorization("snap", "token")
    )


@pytest.mark.parametrize(
    "path",
    [
        "/proxy/http%3A%2F%2Fexample.com",
        "/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest",
        "/fetch?destination=example.com%3A80",
    ],
)
def test_http_path_cannot_smuggle_an_ssrf_destination(path):
    with pytest.raises(SafetyViolation):
        SafetyGate(runtime()).validate_step(
            step(arguments={"method": "GET", "path": path})
        )


def test_query_destination_may_reference_only_an_exact_allowlisted_origin():
    SafetyGate(runtime()).validate_step(
        step(
            arguments={
                "method": "GET",
                "path": "/fetch?url=http%3A%2F%2F127.0.0.1%3A7475%2Ffixture",
            }
        )
    )


@pytest.mark.parametrize(
    "arguments",
    [
        {"callback": "https://example.com/hit"},
        {"nested": {"endpoint": "10.0.0.2:80"}},
        {"items": [{"webhook": "http://192.0.2.2/x"}]},
    ],
)
def test_nested_ssrf_destinations_are_rejected(arguments):
    with pytest.raises(SafetyViolation, match="loopback"):
        SafetyGate(runtime()).validate_step(step(arguments=arguments))


def test_destructive_plan_requires_snapshot_and_matching_secret(monkeypatch):
    config = runtime()
    gate = SafetyGate(config)
    destructive = plan(risk=RiskLevel.DESTRUCTIVE)

    monkeypatch.delenv(config.safety.destructive_token_env, raising=False)
    with pytest.raises(SafetyViolation, match="explicit snapshot"):
        gate.validate_plan(destructive)
    with pytest.raises(SafetyViolation, match="non-empty snapshot"):
        gate.validate_plan(destructive, DestructiveAuthorization("", "token"))
    with pytest.raises(SafetyViolation, match="not configured"):
        gate.validate_plan(destructive, DestructiveAuthorization("snap-1", "token"))

    monkeypatch.setenv(config.safety.destructive_token_env, "expected")
    with pytest.raises(SafetyViolation, match="invalid"):
        gate.validate_plan(destructive, DestructiveAuthorization("snap-1", "wrong"))
    gate.validate_plan(destructive, DestructiveAuthorization("snap-1", "expected"))


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_mutating_http_semantics_require_authorization_even_if_model_says_safe(
    method, monkeypatch
):
    config = runtime()
    candidate = plan(
        step(arguments={"method": method, "path": "/api/v1/state"}),
        risk=RiskLevel.SAFE,
    )

    assert effective_plan_requires_authorization(candidate)
    with pytest.raises(SafetyViolation, match="explicit snapshot"):
        SafetyGate(config).validate_plan(candidate)

    monkeypatch.setenv(config.safety.destructive_token_env, "expected")
    SafetyGate(config).validate_plan(
        candidate, DestructiveAuthorization("snap-1", "expected")
    )


def test_only_narrow_synthetic_mcp_posts_are_non_destructive():
    malformed = step(
        tool="mcp_call",
        arguments={"method": "POST", "path": "/mcp", "body": "{invalid-json"},
    )
    denied_synthetic = step(
        tool="mcp_call",
        arguments={
            "method": "POST",
            "path": "/mcp",
            "message": {
                "jsonrpc": "2.0",
                "id": "HERACLITUS_REDTEAM_SYNTHETIC_MARKER",
                "method": "tools/call",
                "params": {
                    "name": "heraclitus_redteam_forbidden_probe",
                    "arguments": {
                        "marker": "HERACLITUS_REDTEAM_SYNTHETIC_MARKER"
                    },
                },
            },
        },
    )
    dangerous = step(
        tool="mcp_call",
        arguments={
            "method": "POST",
            "path": "/mcp",
            "message": {
                "jsonrpc": "2.0",
                "id": "1",
                "method": "tools/call",
                "params": {"name": "drop_database", "arguments": {}},
            },
        },
    )

    assert not effective_step_requires_authorization(malformed)
    assert not effective_step_requires_authorization(denied_synthetic)
    assert effective_step_requires_authorization(dangerous)
    SafetyGate(runtime()).validate_plan(plan(malformed))
    SafetyGate(runtime()).validate_plan(plan(denied_synthetic))
    with pytest.raises(SafetyViolation, match="explicit snapshot"):
        SafetyGate(runtime()).validate_plan(plan(dangerous))


def test_snapshot_can_be_optional_but_token_remains_required(monkeypatch):
    config = RuntimeConfig(
        safety=SafetyConfig(
            require_snapshot_for_destructive=False,
            allowed_targets=frozenset({"http://127.0.0.1:7475"}),
        )
    )
    monkeypatch.setenv(config.safety.destructive_token_env, "token")
    SafetyGate(config).validate_plan(
        plan(risk=RiskLevel.DESTRUCTIVE),
        DestructiveAuthorization("", "token"),
    )
