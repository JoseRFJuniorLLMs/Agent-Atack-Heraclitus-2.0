import json

import pytest

from heraclitus_attack.config import BudgetConfig, RuntimeConfig, SafetyConfig


@pytest.mark.parametrize(
    "field",
    [
        "max_plans",
        "max_steps_per_plan",
        "max_requests_per_plan",
        "max_concurrency",
        "max_payload_bytes",
        "max_response_bytes",
        "confirmation_runs",
        "step_timeout_seconds",
        "plan_timeout_seconds",
        "campaign_timeout_seconds",
    ],
)
def test_budget_fields_must_be_positive(field):
    with pytest.raises(ValueError, match=field):
        BudgetConfig(**{field: 0})


def test_timeout_hierarchy_is_enforced():
    with pytest.raises(ValueError, match="step timeout"):
        BudgetConfig(step_timeout_seconds=10, plan_timeout_seconds=9)
    with pytest.raises(ValueError, match="plan timeout"):
        BudgetConfig(plan_timeout_seconds=100, campaign_timeout_seconds=99)


def test_safety_config_rejects_empty_or_invalid_adapter_names():
    with pytest.raises(ValueError, match="cannot be empty"):
        SafetyConfig(allowed_tools=frozenset())
    with pytest.raises(ValueError, match="invalid adapter"):
        SafetyConfig(allowed_tools=frozenset({"shell;rm"}))


def test_runtime_config_is_strict_and_normalises_sets():
    config = RuntimeConfig.from_dict(
        {
            "budgets": {"max_plans": 2},
            "safety": {
                "allowed_tools": ["tcp_probe"],
                "allowed_http_methods": ["get", "post"],
            },
            "user_agent": "test-agent",
        }
    )
    assert config.budgets.max_plans == 2
    assert config.safety.allowed_tools == frozenset({"tcp_probe"})
    assert config.safety.allowed_http_methods == frozenset({"GET", "POST"})
    assert config.user_agent == "test-agent"
    with pytest.raises(ValueError, match="unknown RuntimeConfig"):
        RuntimeConfig.from_dict({"target": "example.com"})


def test_runtime_config_json_and_file_loading(tmp_path):
    payload = {"budgets": {"max_concurrency": 1}, "safety": {}}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert RuntimeConfig.load(path) == RuntimeConfig.from_json(json.dumps(payload))
    with pytest.raises(ValueError, match="root"):
        RuntimeConfig.from_json("[]")


def test_destructive_token_is_read_lazily(monkeypatch):
    config = RuntimeConfig()
    monkeypatch.delenv(config.safety.destructive_token_env, raising=False)
    assert config.expected_destructive_token() is None
    monkeypatch.setenv(config.safety.destructive_token_env, "  secret  ")
    assert config.expected_destructive_token() == "secret"


@pytest.mark.parametrize("name", ["smoke.json", "disposable-nightly.json"])
def test_repository_examples_match_runtime_schema(name):
    # Resolve from the checkout, not the current process directory used by CI.
    path = __file__.replace("tests\\test_config.py", f"config\\{name}")
    if path == __file__:
        from pathlib import Path

        path = str(Path(__file__).parents[1] / "config" / name)
    RuntimeConfig.load(path)

