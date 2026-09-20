"""Command-line interface and long-running WSL service loop."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import os
from pathlib import Path
import signal
import socket
from threading import Event
import time
from typing import Iterable, Sequence
from urllib.parse import urlsplit

from .agents import AgentContext, AgentPipeline
from .arena import (
    ArenaError,
    ArenaLimits,
    DEFAULT_CATALOG,
    DEFAULT_LEGACY_ROOT,
    DEFAULT_SERVER_BINARY,
    RemoteEndpoint,
    run_arena,
)
from .catalog import plans_for_profile
from .console import BootConsole
from .coordinator import CampaignReport, Coordinator
from .credentials import authenticated_tool_registry
from .executor import SafeToolExecutor
from .memory import HeraclitusMemorySink, MemorySink, UntrustedMemoryRecord
from .models import AttackPlan, Finding, RiskLevel, Verdict, new_id, utc_now
from .oracles import OracleRegistry, default_oracles
from .providers import (
    AnthropicProvider,
    GeminiProvider,
    MockProvider,
    OpenAICompatibleProvider,
    OpenAIResponsesProvider,
    ProviderRoute,
    RoutingProvider,
)
from .reporting import PersistResult, persist_findings, write_report
from .safety import (
    DestructiveAuthorization,
    SafetyGate,
    effective_plan_requires_authorization,
    is_remote_target,
)
from .settings import LabSettings


DEFAULT_CONFIG = "config/smoke.json"
EXIT_OK = 0
EXIT_VULNERABLE = 2
EXIT_INCONCLUSIVE = 3
EXIT_ERROR = 4


class CliError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class RunOutcome:
    report: CampaignReport
    report_path: Path
    persistence: PersistResult | None
    harness_errors: tuple[str, ...] = ()
    evidence_errors: tuple[str, ...] = ()

    @property
    def exit_code(self) -> int:
        if self.harness_errors or self.report.verdict is Verdict.ERROR:
            return EXIT_ERROR
        if self.report.verdict is Verdict.VULNERABLE:
            return EXIT_VULNERABLE
        if self.evidence_errors or self.report.verdict in {Verdict.FAIL, Verdict.INCONCLUSIVE}:
            return EXIT_INCONCLUSIVE
        return EXIT_OK


def _provider_from_settings(config, *, use_global_overrides: bool = False):
    if config.kind == "mock":
        return MockProvider()
    base_url = (
        os.getenv("HERACLITUS_LLM_BASE_URL", config.base_url)
        if use_global_overrides
        else config.base_url
    )
    model = (
        os.getenv("HERACLITUS_LLM_MODEL", config.model)
        if use_global_overrides
        else config.model
    )
    api_key = os.getenv(config.api_key_env) or None
    common = dict(
        base_url=base_url,
        model=model,
        api_key=api_key,
        timeout_seconds=config.timeout_seconds,
    )
    if config.kind == "openai-compatible":
        return OpenAICompatibleProvider(**common)
    if config.kind == "openai-responses":
        return OpenAIResponsesProvider(**common)
    if config.kind == "anthropic":
        return AnthropicProvider(**common)
    if config.kind == "gemini":
        return GeminiProvider(**common)
    raise AssertionError(f"unknown provider kind: {config.kind}")


def _provider(settings: LabSettings):
    if not settings.providers:
        return _provider_from_settings(settings.provider, use_global_overrides=True)
    routes = []
    for index, config in enumerate(settings.providers, start=1):
        routes.append(
            ProviderRoute(
                name=config.name or f"{config.kind}-{index}",
                provider=_provider_from_settings(config),
                roles=frozenset(config.roles),
            )
        )
    return RoutingProvider(routes)


def _memory_sink(settings: LabSettings) -> HeraclitusMemorySink:
    return HeraclitusMemorySink(
        base_url=settings.targets.agent_api,
        bearer_token=os.getenv("HERACLITUS_AGENT_TOKEN") or None,
    )


def _load_plans(paths: Iterable[str]) -> list[AttackPlan]:
    plans: list[AttackPlan] = []
    for raw in paths:
        path = Path(raw)
        try:
            plans.append(AttackPlan.from_json(path.read_bytes()))
        except OSError as exc:
            raise CliError(f"não foi possível ler o plano {path}: {type(exc).__name__}") from exc
        except ValueError as exc:
            raise CliError(f"plano inválido em {path}: {exc}") from exc
    return plans


def _attack_target(plan: AttackPlan) -> str:
    for step in plan.steps:
        if step.tool != "upstream_counter":
            return step.target
    return plan.steps[0].target


def _agentic_variations(
    settings: LabSettings,
    seeds: Sequence[AttackPlan],
    *,
    campaign_id: str,
    memories: Sequence[UntrustedMemoryRecord],
    console: BootConsole,
    enabled: bool = True,
) -> tuple[list[AttackPlan], list[str]]:
    capacity = max(0, settings.runtime.budgets.max_plans - len(seeds))
    requested = min(settings.campaign.plans_per_cycle, capacity, len(seeds))
    if not enabled or not settings.campaign.agentic or requested == 0:
        return [], []
    provider = _provider(settings)
    pipeline = AgentPipeline(provider)
    oracle_ids = OracleRegistry().ids
    ordered_seeds = sorted(
        seeds,
        key=lambda item: item.metadata.get("diagnostic_only") is True,
    )
    max_risk = (
        RiskLevel.DESTRUCTIVE
        if settings.campaign.profile == "destructive"
        else RiskLevel.ELEVATED
    )
    plans: list[AttackPlan] = []
    errors: list[str] = []
    for index, seed in enumerate(ordered_seeds[:requested], start=1):
        console.line(
            "RUN",
            f"agentes vivos {index}/{requested}",
            "recon → planner → critic → mutator → critic → minimizer",
        )
        context = AgentContext(
            campaign_id=campaign_id,
            target=_attack_target(seed),
            objective=seed.hypothesis,
            allowed_tools=tuple(sorted(settings.runtime.safety.allowed_tools)),
            # Keep every mutation inside the exact surface of its curated
            # seed. Multi-target seeds (for example MCP + synthetic upstream)
            # retain only those explicit origins.
            allowed_targets=tuple(dict.fromkeys(step.target for step in seed.steps)),
            allowed_oracles=oracle_ids,
            observations=tuple(memories),
            prior_plans=(seed,),
            max_steps=settings.runtime.budgets.max_steps_per_plan,
            max_step_timeout_seconds=settings.runtime.budgets.step_timeout_seconds,
            max_risk=max_risk,
        )
        try:
            plans.append(pipeline.run(context, seed=seed).plan)
        except Exception as exc:
            marker = f"agentic-{index}:{type(exc).__name__}"
            errors.append(marker)
            console.line(
                "ERROR",
                f"pipeline agêntico {index}",
                f"falhou fechado ({type(exc).__name__}); plano não será executado",
            )
    return plans, errors


def _authorization(
    settings: LabSettings,
    *,
    snapshot_id: str | None,
    plans: Sequence[AttackPlan],
) -> DestructiveAuthorization | None:
    destructive = settings.campaign.profile == "destructive" or any(
        effective_plan_requires_authorization(plan) for plan in plans
    )
    if not destructive:
        return None
    if not snapshot_id or not snapshot_id.strip():
        raise CliError("campanha destrutiva exige --snapshot-id de uma cópia descartável")
    token = settings.runtime.expected_destructive_token()
    if not token:
        raise CliError(
            f"defina {settings.runtime.safety.destructive_token_env} para esta sessão supervisionada"
        )
    return DestructiveAuthorization(snapshot_id=snapshot_id.strip(), token=token)


def _remote_lab_authorization(
    settings: LabSettings,
    *,
    acknowledged: bool,
    run_id: str | None,
) -> None:
    remote = [
        target for target in settings.targets.to_dict().values() if is_remote_target(target)
    ]
    if not remote:
        return
    if settings.campaign.profile != "remote-lab":
        raise CliError("destinos remotos exigem campaign.profile=remote-lab")
    if not acknowledged:
        raise CliError("remote-lab exige --i-understand-remote-lab")
    if not run_id or not run_id.strip():
        raise CliError("remote-lab exige --remote-run-id para correlacionar a janela autorizada")
    if not settings.runtime.expected_remote_lab_token():
        raise CliError(
            f"defina {settings.runtime.safety.remote_lab_token_env} para autorizar o alvo remoto"
        )


def run_once(
    settings: LabSettings,
    *,
    console: BootConsole | None = None,
    plan_paths: Sequence[str] = (),
    disable_agentic: bool = False,
    disable_persistence: bool = False,
    snapshot_id: str | None = None,
    remote_acknowledged: bool = False,
    remote_run_id: str | None = None,
) -> RunOutcome:
    output = console or BootConsole()
    campaign_id = new_id("campaign")
    started_at = utc_now()
    started = time.monotonic()
    target_scope = (
        "private-remote"
        if any(
            is_remote_target(target)
            for target in settings.targets.to_dict().values()
        )
        else "loopback-only"
    )
    output.banner(
        "HERACLITUS ATTACK 2.0",
        f"campanha={campaign_id} · perfil={settings.campaign.profile} · alvo={target_scope}",
    )
    _remote_lab_authorization(
        settings,
        acknowledged=remote_acknowledged,
        run_id=remote_run_id,
    )

    custom = _load_plans(plan_paths)
    if settings.campaign.profile == "destructive" and not custom:
        raise CliError(
            "o perfil destructive não inventa corrupção automaticamente; forneça --plan em instância descartável"
        )
    fixed = custom or list(plans_for_profile(settings))
    if len(fixed) > settings.runtime.budgets.max_plans:
        raise CliError("catálogo fixo excede runtime.budgets.max_plans")

    sink: MemorySink | None = None
    memories: Sequence[UntrustedMemoryRecord] = ()
    persistence_enabled = settings.campaign.persist_evidence and not disable_persistence
    memory_errors: list[str] = []
    if persistence_enabled:
        sink = _memory_sink(settings)
        try:
            memories = sink.recent(limit=25)
            output.line("PASS", "memória HeraclitusDB", f"{len(memories)} eventos recentes carregados como dados não confiáveis")
        except Exception as exc:
            memory_errors.append(f"memory-read:{type(exc).__name__}")
            output.line(
                "INCONCLUSIVE",
                "memória HeraclitusDB",
                f"indisponível ({type(exc).__name__}); a campanha continua sem memória adaptativa",
            )

    variations, agent_errors = _agentic_variations(
        settings,
        fixed,
        campaign_id=campaign_id,
        memories=memories,
        console=output,
        enabled=not disable_agentic,
    )
    plans = [*fixed, *variations]
    authorization = _authorization(settings, snapshot_id=snapshot_id, plans=plans)

    registry = authenticated_tool_registry(
        core_rest=settings.targets.core_rest,
        agent_api=settings.targets.agent_api,
        mcp_gateway=settings.targets.mcp_gateway,
    )
    gate = SafetyGate(settings.runtime)
    executor = SafeToolExecutor(settings.runtime, registry=registry, gate=gate)
    oracle_items = default_oracles()
    coordinator = Coordinator(
        executor=executor,
        oracles={item.oracle_id: item for item in oracle_items},
        config=settings.runtime,
    )

    findings: list[Finding] = []
    for index, plan in enumerate(plans, start=1):
        output.line("RUN", f"teste {index}/{len(plans)}", plan.title)
        finding = coordinator.run_plan(
            plan,
            campaign_id=campaign_id,
            authorization=authorization,
        )
        findings.append(finding)
        output.attack(
            plan.title,
            finding.verdict,
            f"tentativas={finding.attempts}; confirmações={finding.confirmations}; id={finding.finding_id}",
            diagnostic=bool(plan.metadata.get("diagnostic_only")),
        )

    report = CampaignReport(
        campaign_id=campaign_id,
        started_at=started_at,
        duration_ms=(time.monotonic() - started) * 1000,
        findings=tuple(findings),
    )
    persisted: PersistResult | None = None
    if sink is not None:
        persisted = persist_findings(sink, plans, findings)
        if persisted.errors:
            memory_errors.extend(persisted.errors)
            output.line(
                "INCONCLUSIVE",
                "evidência HeraclitusDB",
                f"{len(persisted.errors)} evento(s) não persistido(s); nenhum PASS foi inventado",
            )
        else:
            output.line(
                "PASS",
                "evidência HeraclitusDB",
                f"{len(persisted.receipts)} evento(s) append-only persistido(s)",
            )

    path = write_report(
        report,
        plans=plans,
        report_dir=settings.campaign.report_dir,
        persistence=persisted,
    )
    counts = Counter(item.verdict.value.upper() for item in findings)
    harness_errors = tuple([*agent_errors])
    # A memory outage is visible and makes adaptive/persistence guarantees
    # inconclusive, but does not misclassify the database attack result.
    if memory_errors:
        counts["INCONCLUSIVE"] += len(memory_errors)
    provisional = RunOutcome(
        report,
        path,
        persisted,
        harness_errors,
        tuple(memory_errors),
    )
    output.summary(dict(counts), provisional.exit_code)
    output.line("INFO", "relatório", str(path.resolve()))
    return provisional


def _target_socket(target: str) -> tuple[str, int]:
    if target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        assert parsed.hostname is not None
        return parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    host, _, raw_port = target.rpartition(":")
    return host.strip("[]"), int(raw_port)


def doctor(settings: LabSettings, *, console: BootConsole | None = None) -> int:
    output = console or BootConsole()
    output.banner("HERACLITUS ATTACK DOCTOR", "validação local; nenhuma carga ofensiva é enviada")
    output.line(
        "PASS",
        "fronteira de segurança",
        f"{len(settings.runtime.safety.allowed_targets)} destinos exatos e somente loopback",
    )
    mandatory = {"core_rest", "core_grpc"}
    failed_mandatory = False
    for name, target in settings.targets.to_dict().items():
        host, port = _target_socket(target)
        try:
            with socket.create_connection((host, port), timeout=1.5):
                pass
            output.line("PASS", name, f"{target} alcançável")
        except OSError:
            status = "ERROR" if name in mandatory else "INCONCLUSIVE"
            output.line(status, name, f"{target} não respondeu ao probe TCP")
            failed_mandatory |= name in mandatory
    if settings.provider.kind == "mock":
        output.line("PASS", "provedor LLM", "mock determinístico; nenhuma rede externa")
    else:
        try:
            _provider(settings)
            output.line("PASS", "provedor LLM", "endpoint configurado e cliente validado; chamada não enviada")
        except Exception as exc:
            output.line("ERROR", "provedor LLM", f"configuração inválida ({type(exc).__name__})")
            failed_mandatory = True
    return EXIT_ERROR if failed_mandatory else EXIT_OK


def _settings(path: str) -> LabSettings:
    try:
        return LabSettings.load(path)
    except OSError as exc:
        raise CliError(f"não foi possível ler a configuração: {type(exc).__name__}") from exc
    except (TypeError, ValueError) as exc:
        raise CliError(f"configuração inválida: {exc}") from exc


def _install_signals(stop: Event) -> None:
    def request_stop(signum, frame):  # noqa: ANN001
        del signum, frame
        stop.set()

    for name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), request_stop)


def daemon(
    settings: LabSettings,
    *,
    console: BootConsole | None = None,
    disable_agentic: bool = False,
    disable_persistence: bool = False,
) -> int:
    if settings.campaign.profile in {"destructive", "remote-lab"}:
        raise CliError(
            "daemon 24/7 recusa perfil destructive/remote-lab; execute-o manualmente"
        )
    if any(is_remote_target(target) for target in settings.targets.to_dict().values()):
        raise CliError("daemon 24/7 recusa qualquer destino remoto")
    output = console or BootConsole()
    stop = Event()
    _install_signals(stop)
    cycle = 0
    worst = EXIT_OK
    while not stop.is_set():
        cycle += 1
        output.line("RUN", "ciclo do serviço", f"ciclo={cycle}")
        try:
            outcome = run_once(
                settings,
                console=output,
                disable_agentic=disable_agentic,
                disable_persistence=disable_persistence,
            )
            worst = max(worst, outcome.exit_code)
        except Exception as exc:
            worst = max(worst, EXIT_ERROR)
            output.line(
                "ERROR",
                "ciclo do serviço",
                f"falhou fechado ({type(exc).__name__}); novo ciclo será tentado",
            )
        if settings.campaign.max_cycles is not None and cycle >= settings.campaign.max_cycles:
            break
        output.line("INFO", "próximo ciclo", f"em {settings.campaign.interval_seconds:g}s")
        stop.wait(settings.campaign.interval_seconds)
    output.line("INFO", "serviço", "encerrado de forma controlada")
    # SIGINT/SIGTERM from systemd is an expected operational stop. Findings
    # from earlier cycles remain in their reports, but must not make the unit
    # look crashed or trigger Restart=on-failure during a clean shutdown.
    return EXIT_OK if stop.is_set() else worst


def arena_command(
    settings: LabSettings,
    *,
    console: BootConsole,
    acknowledged: bool,
    snapshot_id: str | None,
    server_binary: str,
    catalog_path: str,
    legacy_root: str | None,
    bwrap_binary: str,
    max_actions: int,
    command_timeout_seconds: float,
    session_timeout_seconds: float,
    max_output_bytes: int,
    remote_acknowledged: bool = False,
    remote_run_id: str | None = None,
) -> int:
    """Run the explicitly supervised arbitrary-shell arena."""

    if not acknowledged:
        raise CliError(
            "a arena exige --i-understand-isolated-shell; ela destrói o clone tmpfs ao encerrar"
        )
    if not snapshot_id or not snapshot_id.strip():
        raise CliError("a arena exige --snapshot-id identificando a cópia descartável")
    if not settings.runtime.expected_destructive_token():
        raise CliError(
            f"defina {settings.runtime.safety.destructive_token_env} para abrir a arena supervisionada"
        )
    remote_targets = any(
        is_remote_target(target) for target in settings.targets.to_dict().values()
    )
    if remote_targets:
        _remote_lab_authorization(
            settings,
            acknowledged=remote_acknowledged,
            run_id=remote_run_id,
        )
    elif settings.campaign.profile != "destructive":
        raise CliError(
            "a arena local exige campaign.profile=destructive; a remota exige remote-lab"
        )
    limits = ArenaLimits(
        max_actions=max_actions,
        command_timeout_seconds=command_timeout_seconds,
        session_timeout_seconds=session_timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    local_ports = {
        "core_rest": 17475,
        "core_grpc": 17474,
        "agent_api": 18080,
        "mcp_gateway": 18787,
        "otlp": 14318,
        "upstream": 19000,
    }
    remote_endpoints: list[RemoteEndpoint] = []
    if remote_targets:
        for name, target in settings.targets.to_dict().items():
            host, port = _target_socket(target)
            remote_endpoints.append(
                RemoteEndpoint(name, local_ports[name], host, port)
            )
    run_arena(
        provider=_provider(settings),
        server_binary=None if remote_targets else server_binary,
        catalog_path=catalog_path,
        legacy_root=legacy_root,
        report_dir=settings.campaign.report_dir,
        console=console,
        limits=limits,
        bwrap_binary=bwrap_binary,
        remote_endpoints=tuple(remote_endpoints),
    )
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="heraclitus-attack",
        description="Red-team agentico isolado e autorizado para HeraclitusDB",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 2.0.0")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(name: str, help_text: str) -> argparse.ArgumentParser:
        command = sub.add_parser(name, help=help_text)
        command.add_argument("--config", default=DEFAULT_CONFIG)
        return command

    common("doctor", "validar configuração e listeners locais")
    common("show-config", "mostrar configuração efetiva sem segredos")
    run = common("run", "executar uma campanha")
    run.add_argument("--plan", action="append", default=[], help="AttackPlan JSON tipado; repetível")
    run.add_argument("--no-agentic", action="store_true", help="executar apenas o catálogo determinístico")
    run.add_argument("--no-persist", action="store_true", help="não anexar metadados ao HeraclitusDB")
    run.add_argument("--snapshot-id", help="snapshot descartável exigido para plano destrutivo")
    run.add_argument(
        "--i-understand-remote-lab",
        action="store_true",
        help="autorizar os IPs privados exatos do perfil remote-lab",
    )
    run.add_argument("--remote-run-id", help="ID auditável da janela de teste remoto")

    service = common("daemon", "executar campanhas smoke continuamente")
    service.add_argument("--no-agentic", action="store_true")
    service.add_argument("--no-persist", action="store_true")

    arena = common(
        "arena",
        "dar shell Linux autônomo ao LLM dentro de clone Bubblewrap descartável",
    )
    arena.set_defaults(config="config/arena.json")
    arena.add_argument("--snapshot-id", required=True)
    arena.add_argument(
        "--i-understand-isolated-shell",
        action="store_true",
        help="confirmar execução destrutiva somente no clone tmpfs isolado",
    )
    arena.add_argument("--server-binary", default=DEFAULT_SERVER_BINARY)
    arena.add_argument("--catalog", default=DEFAULT_CATALOG)
    arena.add_argument("--legacy-root", default=DEFAULT_LEGACY_ROOT)
    arena.add_argument("--bwrap", default="/usr/bin/bwrap")
    arena.add_argument("--max-actions", type=int, default=24)
    arena.add_argument("--command-timeout", type=float, default=25.0)
    arena.add_argument("--session-timeout", type=float, default=900.0)
    arena.add_argument("--max-output-bytes", type=int, default=65_536)
    arena.add_argument("--i-understand-remote-lab", action="store_true")
    arena.add_argument("--remote-run-id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = BootConsole()
    try:
        settings = _settings(args.config)
        if args.command == "doctor":
            return doctor(settings, console=console)
        if args.command == "show-config":
            print(settings.to_json())
            return EXIT_OK
        if args.command == "run":
            outcome = run_once(
                settings,
                console=console,
                plan_paths=args.plan,
                disable_agentic=args.no_agentic,
                disable_persistence=args.no_persist,
                snapshot_id=args.snapshot_id,
                remote_acknowledged=args.i_understand_remote_lab,
                remote_run_id=args.remote_run_id,
            )
            return outcome.exit_code
        if args.command == "daemon":
            return daemon(
                settings,
                console=console,
                disable_agentic=args.no_agentic,
                disable_persistence=args.no_persist,
            )
        if args.command == "arena":
            return arena_command(
                settings,
                console=console,
                acknowledged=args.i_understand_isolated_shell,
                snapshot_id=args.snapshot_id,
                server_binary=args.server_binary,
                catalog_path=args.catalog,
                legacy_root=args.legacy_root,
                bwrap_binary=args.bwrap,
                max_actions=args.max_actions,
                command_timeout_seconds=args.command_timeout,
                session_timeout_seconds=args.session_timeout,
                max_output_bytes=args.max_output_bytes,
                remote_acknowledged=args.i_understand_remote_lab,
                remote_run_id=args.remote_run_id,
            )
        raise AssertionError(f"unknown command: {args.command}")
    except (CliError, ArenaError) as exc:
        console.line("ERROR", "comando recusado", str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        console.line("INFO", "interrompido", "solicitação do operador")
        return 130
    except Exception as exc:
        console.line(
            "ERROR",
            "falha interna",
            f"{type(exc).__name__}; nenhum diagnóstico do banco foi emitido",
        )
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
