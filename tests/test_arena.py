import io
import json
from pathlib import Path
import socket
import threading

import pytest

from heraclitus_attack.arena import (
    ACTION_SCHEMA,
    ArenaAction,
    ArenaError,
    ArenaLimits,
    RemoteEndpoint,
    RemoteRelaySet,
    build_bwrap_command,
    run_arena,
)
from heraclitus_attack.console import BootConsole
from heraclitus_attack.providers import MockProvider


def touch(path: Path, text: str = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def catalog(path: Path) -> Path:
    return touch(path, json.dumps({"families": [{"id": "T01", "name": "temporal"}]}))


def test_arena_action_is_strict():
    action = ArenaAction.from_mapping(
        {
            "command": "curl -fsS $HERACLITUS_REST_URL/healthz",
            "rationale": "probe",
            "hypothesis": "healthy",
            "done": False,
            "candidate_title": "",
        }
    )
    assert action.command.startswith("curl")
    with pytest.raises(ArenaError, match="unknown fields"):
        ArenaAction.from_mapping(
            {
                "command": "id",
                "rationale": "probe",
                "hypothesis": "isolated",
                "done": False,
                "candidate_title": "",
                "host_path": "C:/Users",
            }
        )
    with pytest.raises(ArenaError, match="requires a command"):
        ArenaAction.from_mapping(
            {
                "command": "",
                "rationale": "probe",
                "hypothesis": "isolated",
                "done": False,
                "candidate_title": "",
            }
        )
    assert ACTION_SCHEMA["additionalProperties"] is False


def test_arena_limits_reject_unbounded_values():
    with pytest.raises(ValueError, match="max_actions"):
        ArenaLimits(max_actions=0)
    with pytest.raises(ValueError, match="command timeout"):
        ArenaLimits(command_timeout_seconds=121)
    with pytest.raises(ValueError, match="output limit"):
        ArenaLimits(max_output_bytes=2_000_000)


def test_remote_endpoint_accepts_only_literal_non_public_addresses():
    assert RemoteEndpoint("core", 17475, "127.0.0.1", 7475).host == "127.0.0.1"
    assert RemoteEndpoint("core", 17475, "192.168.56.20", 7475).remote_port == 7475
    with pytest.raises(ValueError, match="literal IP"):
        RemoteEndpoint("core", 17475, "db.example.test", 7475)
    with pytest.raises(ValueError, match="private"):
        RemoteEndpoint("core", 17475, "8.8.8.8", 7475)


def test_bwrap_command_hides_host_and_mounts_curated_legacy_files(tmp_path):
    bwrap = touch(tmp_path / "bwrap")
    server = touch(tmp_path / "heraclitus-server")
    worker = touch(tmp_path / "arena_worker.py")
    attacks = catalog(tmp_path / "attack-families.json")
    legacy = tmp_path / "legacy"
    runner = touch(legacy / "runner.py")
    touch(legacy / "private.env", "SECRET=must-not-be-mounted")

    command = build_bwrap_command(
        bwrap_binary=bwrap,
        server_binary=server,
        worker_path=worker,
        catalog_path=attacks,
        legacy_root=legacy,
    )

    assert "--unshare-all" in command
    assert "--share-net" not in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert str(runner.resolve()) in command
    assert str((legacy / "private.env").resolve()) not in command
    assert str(legacy.resolve()) not in command
    assert "/opt/heraclitus/heraclitus-server" in command
    assert "/opt/catalog/attack-families.json" in command


def test_remote_bwrap_has_only_exact_unix_relays_and_no_server_binary(tmp_path):
    bwrap = touch(tmp_path / "bwrap")
    worker = touch(tmp_path / "arena_worker.py")
    attacks = catalog(tmp_path / "attack-families.json")
    relay = tmp_path / "relay"
    relay.mkdir()
    command = build_bwrap_command(
        bwrap_binary=bwrap,
        server_binary=None,
        worker_path=worker,
        catalog_path=attacks,
        legacy_root=None,
        remote_relay_dir=relay,
        remote_map={17475: "/run/relay/core.sock"},
    )
    assert "--unshare-all" in command and "--share-net" not in command
    assert "--bind" in command
    assert str(relay.resolve()) in command
    assert "HERACLITUS_ARENA_MODE" in command
    assert "/opt/heraclitus/heraclitus-server" not in command


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix sockets require Linux/WSL")
def test_remote_relay_forwards_only_configured_endpoint():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def echo():
        connection, _ = listener.accept()
        with connection:
            connection.sendall(connection.recv(1024))
        listener.close()

    threading.Thread(target=echo, daemon=True).start()
    relay = RemoteRelaySet(
        [RemoteEndpoint("core-rest", 17475, "127.0.0.1", port)]
    )
    relay.start()
    try:
        path = relay.relay_dir / f"core-rest-{port}.sock"
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(path))
        client.sendall(b"panta-rhei")
        assert client.recv(64) == b"panta-rhei"
        client.close()
    finally:
        relay.close()
    assert relay.connections == 1
    assert relay.bytes_forwarded >= len(b"panta-rhei") * 2


class FakeSession:
    instances = []

    def __init__(self, command):
        self.command = command
        self.ready = {
            "ready": True,
            "network": "private-loopback-only",
            "filesystem": "tmpfs-with-read-only-tools",
        }
        self.commands = []
        self.__class__.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def execute(self, command, *, timeout_seconds, max_output_bytes):
        self.commands.append((command, timeout_seconds, max_output_bytes))
        return {
            "type": "result",
            "exit_code": 0,
            "timed_out": False,
            "stdout": "panta rhei",
            "stderr": "",
            "stdout_bytes": 10,
            "stderr_bytes": 0,
            "server_alive": True,
            "health_ok": True,
            "health_status": 200,
        }


def test_run_arena_with_mock_provider_writes_discovery_report(tmp_path, monkeypatch):
    # The command builder validates its artifacts before FakeSession receives it.
    bwrap = touch(tmp_path / "bwrap")
    server = touch(tmp_path / "heraclitus-server")
    attacks = catalog(tmp_path / "attack-families.json")
    worker = touch(tmp_path / "arena_worker.py")
    monkeypatch.setattr("heraclitus_attack.arena._worker_path", lambda: worker)
    responses = [
        {
            "command": "curl -fsS $HERACLITUS_REST_URL/healthz",
            "rationale": "test health",
            "hypothesis": "server remains healthy",
            "done": False,
            "candidate_title": "possible temporal bug",
        },
        {
            "command": "",
            "rationale": "finished",
            "hypothesis": "candidate needs an oracle",
            "done": True,
            "candidate_title": "",
        },
    ]
    stream = io.StringIO()

    report, path = run_arena(
        provider=MockProvider(responses),
        server_binary=server,
        catalog_path=attacks,
        legacy_root=None,
        report_dir=tmp_path / "reports",
        console=BootConsole(stream, color=False),
        limits=ArenaLimits(max_actions=2),
        bwrap_binary=bwrap,
        session_factory=FakeSession,
    )

    assert len(report.steps) == 1
    assert report.candidates == ("possible temporal bug",)
    assert report.stop_reason == "agent-finished"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["verdict"] == "discovery-only"
    assert document["isolation"]["network"] == "private-loopback-only"
    assert "aguardando oráculo independente" in stream.getvalue()


def test_run_arena_rejects_malformed_catalog(tmp_path):
    with pytest.raises(ArenaError, match="families array"):
        run_arena(
            provider=MockProvider(),
            server_binary=touch(tmp_path / "server"),
            catalog_path=touch(tmp_path / "bad.json", "{}"),
            legacy_root=None,
            report_dir=tmp_path,
            console=BootConsole(io.StringIO(), color=False),
            bwrap_binary=touch(tmp_path / "bwrap"),
            session_factory=FakeSession,
        )
