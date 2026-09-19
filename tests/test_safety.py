import socket

import pytest

from heraclitus_attack.config import BudgetConfig, RuntimeConfig, SafetyConfig
from heraclitus_attack.models import AttackPlan, AttackStep, RiskLevel
from heraclitus_attack.safety import (
    DestructiveAuthorization,
    SafetyGate,
    SafetyViolation,
    is_loopback_host,
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


def test_gate_accepts_a_bounded_plan():
    SafetyGate(RuntimeConfig()).validate_plan(plan())


def test_gate_rejects_too_many_steps():
    config = RuntimeConfig(budgets=BudgetConfig(max_steps_per_plan=1))
    with pytest.raises(SafetyViolation, match="limit"):
        SafetyGate(config).validate_plan(plan(steps=(step(), step())))


def test_gate_rejects_unknown_tool_remote_target_and_long_timeout():
    gate = SafetyGate(RuntimeConfig())
    with pytest.raises(SafetyViolation, match="allowlisted"):
        gate.validate_step(step(tool="shell"))
    with pytest.raises(SafetyViolation, match="loopback"):
        gate.validate_step(step(target="http://192.0.2.10"))
    with pytest.raises(SafetyViolation, match="timeout"):
        gate.validate_step(step(timeout_seconds=60))


def test_gate_rejects_payload_method_and_absolute_http_path():
    config = RuntimeConfig(budgets=BudgetConfig(max_payload_bytes=32))
    gate = SafetyGate(config)
    with pytest.raises(SafetyViolation, match="payload"):
        gate.validate_step(step(arguments={"body": "x" * 100}))

    gate = SafetyGate(RuntimeConfig())
    with pytest.raises(SafetyViolation, match="method"):
        gate.validate_step(step(arguments={"method": "TRACE", "path": "/"}))
    with pytest.raises(SafetyViolation, match="relative"):
        gate.validate_step(step(arguments={"method": "GET", "path": "http://127.0.0.1/other"}))


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
        SafetyGate(RuntimeConfig()).validate_step(step(arguments=arguments))


def test_destructive_plan_requires_snapshot_and_matching_secret(monkeypatch):
    config = RuntimeConfig()
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


def test_snapshot_can_be_optional_but_token_remains_required(monkeypatch):
    config = RuntimeConfig(
        safety=SafetyConfig(require_snapshot_for_destructive=False)
    )
    monkeypatch.setenv(config.safety.destructive_token_env, "token")
    SafetyGate(config).validate_plan(
        plan(risk=RiskLevel.DESTRUCTIVE),
        DestructiveAuthorization("", "token"),
    )

