from dataclasses import replace
import io
import json
from pathlib import Path

import pytest

from heraclitus_attack import cli
from heraclitus_attack.catalog import smoke_plans
from heraclitus_attack.console import BootConsole
from heraclitus_attack.coordinator import CampaignReport
from heraclitus_attack.memory import InMemoryMemorySink
from heraclitus_attack.models import AttackPlan, AttackStep, Finding, Verdict
from heraclitus_attack.settings import CampaignSettings, LabSettings, ProviderSettings


def settings(tmp_path, **campaign_overrides):
    base = LabSettings()
    campaign = replace(
        base.campaign,
        report_dir=str(tmp_path),
        agentic=False,
        persist_evidence=False,
        **campaign_overrides,
    )
    return replace(base, campaign=campaign)


def finding(verdict=Verdict.PASS, *, title="probe"):
    return Finding(
        campaign_id="campaign-test",
        plan_id="plan-test",
        title=title,
        verdict=verdict,
        reason="typed oracle result",
        attempts=1,
        confirmations=0,
        oracle_results=(),
    )


def report(verdict=Verdict.PASS):
    return CampaignReport(
        campaign_id="campaign-test",
        started_at="2026-01-01T00:00:00+00:00",
        duration_ms=1,
        findings=(finding(verdict),),
    )


@pytest.mark.parametrize(
    "verdict,harness,evidence,expected",
    [
        (Verdict.PASS, (), (), cli.EXIT_OK),
        (Verdict.PASS, ("agent",), (), cli.EXIT_ERROR),
        (Verdict.ERROR, (), (), cli.EXIT_ERROR),
        (Verdict.VULNERABLE, (), (), cli.EXIT_VULNERABLE),
        (Verdict.FAIL, (), (), cli.EXIT_INCONCLUSIVE),
        (Verdict.INCONCLUSIVE, (), (), cli.EXIT_INCONCLUSIVE),
        (Verdict.PASS, (), ("memory",), cli.EXIT_INCONCLUSIVE),
    ],
)
def test_run_outcome_exit_semantics(tmp_path, verdict, harness, evidence, expected):
    outcome = cli.RunOutcome(
        report(verdict), tmp_path / "r.json", None, harness, evidence
    )
    assert outcome.exit_code == expected


def test_provider_selection_honours_kind_and_environment(monkeypatch, tmp_path):
    assert type(cli._provider(settings(tmp_path))).__name__ == "MockProvider"
    live = replace(
        settings(tmp_path),
        provider=ProviderSettings(
            kind="openai-compatible",
            base_url="http://127.0.0.1:11434/v1",
            model="configured",
        ),
    )
    monkeypatch.setenv("HERACLITUS_LLM_MODEL", "override")
    provider = cli._provider(live)
    assert provider.model == "override"
    assert provider.endpoint.endswith("/v1/chat/completions")


def test_load_plans_and_attack_target(tmp_path):
    plan = AttackPlan(
        title="typed",
        hypothesis="bounded",
        steps=(
            AttackStep(tool="upstream_counter", target="http://127.0.0.1:19000"),
            AttackStep(tool="http_request", target="http://127.0.0.1:7475"),
        ),
        oracle_ids=("http_status",),
    )
    path = tmp_path / "plan.json"
    path.write_text(plan.to_json(), encoding="utf-8")
    loaded = cli._load_plans([str(path)])
    assert loaded[0].title == "typed"
    assert cli._attack_target(loaded[0]) == "http://127.0.0.1:7475"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(cli.CliError, match="plano inválido"):
        cli._load_plans([str(path)])
    with pytest.raises(cli.CliError, match="não foi possível ler"):
        cli._load_plans([str(tmp_path / "missing")])


def test_agentic_variation_runs_all_roles_with_mock(tmp_path):
    configured = replace(
        settings(tmp_path),
        campaign=CampaignSettings(
            report_dir=str(tmp_path),
            plans_per_cycle=1,
            agentic=True,
            persist_evidence=False,
        ),
    )
    seed = smoke_plans(configured)[1]
    stream = io.StringIO()
    plans, errors = cli._agentic_variations(
        configured,
        [seed],
        campaign_id="campaign-agentic",
        memories=(),
        console=BootConsole(stream, color=False),
    )
    assert not errors
    assert len(plans) == 1
    assert plans[0].campaign_id == "campaign-agentic"
    assert plans[0].metadata["agent_role"] == "policy-boundary"
    assert plans[0].metadata["oracle_contract_source"] == seed.plan_id
    assert plans[0].oracle_ids == seed.oracle_ids
    assert "recon" in stream.getvalue()


def test_agentic_variations_prioritize_attack_seeds_over_diagnostics(tmp_path):
    configured = replace(
        settings(tmp_path),
        campaign=CampaignSettings(
            report_dir=str(tmp_path),
            plans_per_cycle=1,
            agentic=True,
            persist_evidence=False,
        ),
    )
    seeds = smoke_plans(configured)

    plans, errors = cli._agentic_variations(
        configured,
        seeds,
        campaign_id="campaign-priority",
        memories=(),
        console=BootConsole(io.StringIO(), color=False),
    )

    assert not errors
    expected_seed = next(
        item for item in seeds if item.metadata.get("diagnostic_only") is not True
    )
    assert plans[0].metadata["oracle_contract_source"] == expected_seed.plan_id


def test_agentic_variation_fails_closed(monkeypatch, tmp_path):
    configured = replace(
        settings(tmp_path),
        campaign=replace(settings(tmp_path).campaign, agentic=True, plans_per_cycle=1),
    )

    def fail(*args, **kwargs):
        raise RuntimeError("reflected secret")

    monkeypatch.setattr(cli.AgentPipeline, "run", fail)
    stream = io.StringIO()
    plans, errors = cli._agentic_variations(
        configured,
        [smoke_plans(configured)[0]],
        campaign_id="campaign-agentic",
        memories=(),
        console=BootConsole(stream, color=False),
    )
    assert plans == []
    assert errors == ["agentic-1:RuntimeError"]
    assert "reflected secret" not in stream.getvalue()


def test_destructive_authorization_requires_snapshot_and_env(monkeypatch, tmp_path):
    configured = settings(tmp_path)
    safe = smoke_plans(configured)[0]
    assert cli._authorization(configured, snapshot_id=None, plans=[safe]) is None
    destructive = replace(safe, risk="destructive")
    with pytest.raises(cli.CliError, match="snapshot"):
        cli._authorization(configured, snapshot_id=None, plans=[destructive])
    monkeypatch.delenv("HERACLITUS_ATTACK_DESTRUCTIVE_TOKEN", raising=False)
    with pytest.raises(cli.CliError, match="HERACLITUS_ATTACK_DESTRUCTIVE_TOKEN"):
        cli._authorization(configured, snapshot_id="snap", plans=[destructive])
    monkeypatch.setenv("HERACLITUS_ATTACK_DESTRUCTIVE_TOKEN", "token")
    auth = cli._authorization(configured, snapshot_id="snap", plans=[destructive])
    assert auth.snapshot_id == "snap" and auth.token == "token"


def test_run_once_writes_report_and_fedora_log(monkeypatch, tmp_path):
    configured = settings(tmp_path)

    def fake_run(self, plan, **kwargs):
        return Finding(
            campaign_id=kwargs["campaign_id"],
            plan_id=plan.plan_id,
            title=plan.title,
            verdict=Verdict.PASS,
            reason="blocked",
            attempts=1,
            confirmations=0,
            oracle_results=(),
        )

    monkeypatch.setattr(cli.Coordinator, "run_plan", fake_run)
    stream = io.StringIO()
    outcome = cli.run_once(
        configured,
        console=BootConsole(stream, color=False),
        disable_agentic=True,
        disable_persistence=True,
    )
    assert outcome.exit_code == 0
    assert outcome.report_path.exists()
    data = json.loads(outcome.report_path.read_text(encoding="utf-8"))
    assert data["verdict"] == "pass"
    assert "ataque NÃO funcionou" in stream.getvalue()


def test_run_once_persists_to_memory_sink(monkeypatch, tmp_path):
    configured = replace(
        settings(tmp_path),
        campaign=replace(settings(tmp_path).campaign, persist_evidence=True),
    )
    sink = InMemoryMemorySink()
    monkeypatch.setattr(cli, "_memory_sink", lambda settings: sink)

    def fake_run(self, plan, **kwargs):
        return Finding(
            campaign_id=kwargs["campaign_id"],
            plan_id=plan.plan_id,
            title=plan.title,
            verdict=Verdict.PASS,
            reason="blocked",
            attempts=1,
            confirmations=0,
            oracle_results=(),
        )

    monkeypatch.setattr(cli.Coordinator, "run_plan", fake_run)
    outcome = cli.run_once(
        configured,
        console=BootConsole(io.StringIO(), color=False),
        disable_agentic=True,
    )
    assert outcome.persistence
    assert len(sink.events) == len(smoke_plans(configured))
    assert not outcome.evidence_errors


class SocketContext:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_doctor_success_and_mandatory_failure(monkeypatch, tmp_path):
    configured = settings(tmp_path)
    monkeypatch.setattr(cli.socket, "create_connection", lambda *a, **k: SocketContext())
    assert cli.doctor(configured, console=BootConsole(io.StringIO(), color=False)) == 0

    def selective(address, **kwargs):
        if address[1] == 7474:
            raise OSError
        return SocketContext()

    monkeypatch.setattr(cli.socket, "create_connection", selective)
    assert cli.doctor(configured, console=BootConsole(io.StringIO(), color=False)) == cli.EXIT_ERROR


def test_daemon_single_cycle_and_destructive_refusal(monkeypatch, tmp_path):
    configured = replace(
        settings(tmp_path),
        campaign=replace(settings(tmp_path).campaign, max_cycles=1),
    )
    monkeypatch.setattr(cli, "_install_signals", lambda stop: None)
    fake = cli.RunOutcome(report(), tmp_path / "r.json", None)
    monkeypatch.setattr(cli, "run_once", lambda *a, **k: fake)
    assert cli.daemon(configured, console=BootConsole(io.StringIO(), color=False)) == 0
    destructive = replace(
        configured,
        campaign=replace(configured.campaign, profile="destructive"),
    )
    with pytest.raises(cli.CliError, match="recusa perfil destructive"):
        cli.daemon(destructive, console=BootConsole(io.StringIO(), color=False))


def test_daemon_returns_success_for_a_controlled_service_stop(monkeypatch, tmp_path):
    configured = settings(tmp_path)
    monkeypatch.setattr(cli, "_install_signals", lambda stop: stop.set())

    assert cli.daemon(
        configured, console=BootConsole(io.StringIO(), color=False)
    ) == cli.EXIT_OK


def test_main_routes_show_config_and_errors(monkeypatch, tmp_path, capsys):
    path = tmp_path / "config.json"
    path.write_text(settings(tmp_path).to_json(), encoding="utf-8")
    assert cli.main(["show-config", "--config", str(path)]) == 0
    assert '"runtime"' in capsys.readouterr().out
    assert cli.main(["show-config", "--config", str(tmp_path / "missing")]) == cli.EXIT_ERROR


def test_arena_command_requires_ack_snapshot_token_and_destructive_profile(monkeypatch, tmp_path):
    configured = replace(
        settings(tmp_path),
        campaign=replace(settings(tmp_path).campaign, profile="destructive"),
    )
    common = dict(
        settings=configured,
        console=BootConsole(io.StringIO(), color=False),
        server_binary="server",
        catalog_path="catalog",
        legacy_root=None,
        bwrap_binary="bwrap",
        max_actions=1,
        command_timeout_seconds=1,
        session_timeout_seconds=1,
        max_output_bytes=1024,
    )
    with pytest.raises(cli.CliError, match="i-understand"):
        cli.arena_command(acknowledged=False, snapshot_id="tmpfs", **common)
    with pytest.raises(cli.CliError, match="snapshot"):
        cli.arena_command(acknowledged=True, snapshot_id=None, **common)
    monkeypatch.delenv("HERACLITUS_ATTACK_DESTRUCTIVE_TOKEN", raising=False)
    with pytest.raises(cli.CliError, match="HERACLITUS_ATTACK_DESTRUCTIVE_TOKEN"):
        cli.arena_command(acknowledged=True, snapshot_id="tmpfs", **common)
    monkeypatch.setenv("HERACLITUS_ATTACK_DESTRUCTIVE_TOKEN", "ephemeral")
    called = {}
    monkeypatch.setattr(cli, "run_arena", lambda **kwargs: called.update(kwargs))
    assert cli.arena_command(acknowledged=True, snapshot_id="tmpfs", **common) == 0
    assert called["limits"].max_actions == 1


def test_target_socket_parsing():
    assert cli._target_socket("http://127.0.0.1:8080") == ("127.0.0.1", 8080)
    assert cli._target_socket("https://[::1]/x") == ("::1", 443)
    assert cli._target_socket("127.0.0.1:7474") == ("127.0.0.1", 7474)


def test_remote_lab_requires_profile_ack_run_id_and_token(monkeypatch):
    repository = Path(__file__).parents[1]
    configured = LabSettings.load(repository / "config" / "remote-lab.example.json")
    monkeypatch.delenv("HERACLITUS_REMOTE_LAB_TOKEN", raising=False)
    with pytest.raises(cli.CliError, match="i-understand"):
        cli._remote_lab_authorization(
            configured, acknowledged=False, run_id="window-1"
        )
    with pytest.raises(cli.CliError, match="remote-run-id"):
        cli._remote_lab_authorization(configured, acknowledged=True, run_id=None)
    with pytest.raises(cli.CliError, match="HERACLITUS_REMOTE_LAB_TOKEN"):
        cli._remote_lab_authorization(
            configured, acknowledged=True, run_id="window-1"
        )
    monkeypatch.setenv("HERACLITUS_REMOTE_LAB_TOKEN", "ephemeral")
    cli._remote_lab_authorization(
        configured, acknowledged=True, run_id="window-1"
    )


def test_arena_remote_lab_builds_exact_relay_endpoints(monkeypatch, tmp_path):
    repository = Path(__file__).parents[1]
    configured = LabSettings.load(repository / "config" / "remote-lab.example.json")
    monkeypatch.setenv("HERACLITUS_REMOTE_LAB_TOKEN", "remote-window")
    monkeypatch.setenv("HERACLITUS_ATTACK_DESTRUCTIVE_TOKEN", "destructive-window")
    called = {}
    monkeypatch.setattr(cli, "run_arena", lambda **kwargs: called.update(kwargs))

    result = cli.arena_command(
        configured,
        console=BootConsole(io.StringIO(), color=False),
        acknowledged=True,
        snapshot_id="remote-disposable-snapshot",
        server_binary="not-needed-in-remote-mode",
        catalog_path="catalog",
        legacy_root=None,
        bwrap_binary="bwrap",
        max_actions=1,
        command_timeout_seconds=1,
        session_timeout_seconds=1,
        max_output_bytes=1024,
        remote_acknowledged=True,
        remote_run_id="window-42",
    )

    assert result == 0
    assert called["server_binary"] is None
    assert len(called["remote_endpoints"]) == 6
    core = next(item for item in called["remote_endpoints"] if item.name == "core_rest")
    assert core.local_port == 17475
    assert (core.host, core.remote_port) == ("192.168.56.20", 7475)
