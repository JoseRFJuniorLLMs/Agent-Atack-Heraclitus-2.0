"""Process supervisor that runs *inside* the disposable Bubblewrap arena.

This module intentionally has no imports from the package.  The host mounts
this single file read-only at ``/opt/arena_worker.py`` and communicates with it
using one JSON object per line.  Arbitrary commands are accepted here because
the worker is already inside a new user, mount, PID, IPC, UTS, cgroup and
network namespace with a tmpfs root for all writable state.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, BinaryIO
from urllib.error import URLError
from urllib.request import build_opener, ProxyHandler, Request


REST_URL = "http://127.0.0.1:17475"
GRPC_ADDR = "127.0.0.1:17474"
CONSOLE_ADDR = "127.0.0.1:18080"
MAX_COMMAND_CHARS = 16_384
ABSOLUTE_MAX_OUTPUT_BYTES = 1_048_576


def _emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, separators=(",", ":")), flush=True)


def _set_limits() -> None:
    """Bound accidents such as fork bombs without restricting shell syntax."""

    limits = (
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_NOFILE, 512),
        (resource.RLIMIT_NPROC, 192),
        (resource.RLIMIT_FSIZE, 256 * 1024 * 1024),
        (resource.RLIMIT_AS, 3 * 1024 * 1024 * 1024),
    )
    for key, ceiling in limits:
        try:
            resource.setrlimit(key, (ceiling, ceiling))
        except (OSError, ValueError):
            # The namespace/cgroup boundary is primary.  A kernel may refuse a
            # secondary rlimit, which is reported in the ready envelope.
            continue


def _health(timeout: float = 0.75) -> tuple[bool, int | None]:
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(Request(f"{REST_URL}/healthz", method="GET"), timeout=timeout) as response:
            response.read(64)
            return response.status == 200, int(response.status)
    except (URLError, TimeoutError, OSError):
        return False, None


def _wait_ready(server: subprocess.Popen[bytes], timeout: float = 12.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if server.poll() is not None:
            return False
        healthy, _ = _health()
        if healthy:
            return True
        time.sleep(0.1)
    return False


def _digest_and_tail(stream: BinaryIO, limit: int) -> tuple[str, str, int, bool]:
    stream.seek(0)
    digest = hashlib.sha256()
    captured = bytearray()
    total = 0
    while True:
        block = stream.read(64 * 1024)
        if not block:
            break
        total += len(block)
        digest.update(block)
        if len(captured) < limit:
            captured.extend(block[: limit - len(captured)])
    return (
        captured.decode("utf-8", "replace"),
        digest.hexdigest(),
        total,
        total > limit,
    )


def _shell_environment() -> dict[str, str]:
    return {
        "HOME": "/arena",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": "/tmp",
        "NO_PROXY": "*",
        "no_proxy": "*",
        "HERACLITUS_REST_URL": REST_URL,
        "HERACLITUS_GRPC_ADDR": GRPC_ADDR,
        "HERACLITUS_CONSOLE_URL": f"http://{CONSOLE_ADDR}",
        "HERACLITUS_DATA_DIR": "/arena/data",
        "HERACLITUS_ATTACK_CATALOG": "/opt/catalog/attack-families.json",
        "HERACLITUS_LEGACY_DIR": "/opt/legacy",
        "PS1": "[arena-heraclitus]# ",
    }


def _execute(
    command: str,
    timeout: float,
    output_limit: int,
    server: subprocess.Popen[bytes] | None,
) -> dict[str, Any]:
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command must be a non-empty string")
    if "\x00" in command or len(command) > MAX_COMMAND_CHARS:
        raise ValueError("command exceeds the arena protocol limit")
    timeout = max(0.1, min(float(timeout), 120.0))
    output_limit = max(1_024, min(int(output_limit), ABSOLUTE_MAX_OUTPUT_BYTES))
    started = time.monotonic()
    timed_out = False
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        child = subprocess.Popen(
            ["/bin/bash", "--noprofile", "--norc", "-lc", command],
            cwd="/arena",
            env=_shell_environment(),
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=True,
        )
        try:
            exit_code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            exit_code = child.wait(timeout=2)
        stdout, stdout_sha256, stdout_bytes, stdout_truncated = _digest_and_tail(
            stdout_file, output_limit
        )
        stderr, stderr_sha256, stderr_bytes, stderr_truncated = _digest_and_tail(
            stderr_file, output_limit
        )
    healthy, health_status = _health()
    return {
        "type": "result",
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "truncated": stdout_truncated or stderr_truncated,
        "server_alive": server.poll() is None if server is not None else None,
        "health_ok": healthy,
        "health_status": health_status,
    }


def _server_environment() -> dict[str, str]:
    value = _shell_environment()
    value.update(
        {
            "HERACLITUS_DATA_DIR": "/arena/data",
            "HERACLITUS_GRPC_ADDR": GRPC_ADDR,
            "HERACLITUS_REST_ADDR": "127.0.0.1:17475",
            "HERACLITUS_AGENT_CONSOLE_ADDR": CONSOLE_ADDR,
            "HERACLITUS_AGENT_ENABLED": "false",
            "RUST_BACKTRACE": "1",
        }
    )
    return value


class _TcpToUnixForwarder:
    """Expose one host-side exact-target relay as loopback inside the arena."""

    def __init__(self, local_port: int, unix_path: str) -> None:
        if not 1 <= local_port <= 65535 or not unix_path.startswith("/run/relay/"):
            raise ValueError("invalid remote relay mapping")
        self.local_port = local_port
        self.unix_path = unix_path
        self.stop = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", local_port))
        self.listener.listen(32)
        self.listener.settimeout(0.25)
        self.thread = threading.Thread(target=self._accept, daemon=True)

    @staticmethod
    def _bridge(left: socket.socket, right: socket.socket) -> None:
        sockets = (left, right)
        try:
            while True:
                readable, _, exceptional = select.select(sockets, (), sockets, 1.0)
                if exceptional:
                    return
                for source in readable:
                    data = source.recv(65_536)
                    if not data:
                        return
                    target = right if source is left else left
                    target.sendall(data)
        finally:
            left.close()
            right.close()

    def _accept(self) -> None:
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                relay = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                relay.connect(self.unix_path)
            except OSError:
                client.close()
                continue
            threading.Thread(
                target=self._bridge, args=(client, relay), daemon=True
            ).start()

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=1)


def _remote_forwarders() -> list[_TcpToUnixForwarder]:
    raw = os.environ.get("HERACLITUS_ARENA_REMOTE_MAP", "")
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid remote relay map") from exc
    if not isinstance(decoded, dict) or not 1 <= len(decoded) <= 16:
        raise ValueError("remote relay map must be a bounded object")
    forwarders: list[_TcpToUnixForwarder] = []
    for raw_port, path in decoded.items():
        forwarders.append(_TcpToUnixForwarder(int(raw_port), str(path)))
    for forwarder in forwarders:
        forwarder.start()
    return forwarders


def main() -> int:
    _set_limits()
    Path("/arena/data").mkdir(parents=True, exist_ok=True)
    log_path = Path("/arena/heraclitus-server.log")
    with log_path.open("ab", buffering=0) as server_log:
        remote_mode = os.environ.get("HERACLITUS_ARENA_MODE") == "remote"
        forwarders: list[_TcpToUnixForwarder] = []
        server: subprocess.Popen[bytes] | None = None
        try:
            if remote_mode:
                forwarders = _remote_forwarders()
                ready = True
            else:
                server = subprocess.Popen(
                    ["/opt/heraclitus/heraclitus-server"],
                    cwd="/arena",
                    env=_server_environment(),
                    stdin=subprocess.DEVNULL,
                    stdout=server_log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                ready = _wait_ready(server)
            _emit(
                {
                    "type": "ready" if ready else "error",
                    "ready": ready,
                    "server_alive": server.poll() is None if server is not None else None,
                    "rest_url": REST_URL,
                    "grpc_addr": GRPC_ADDR,
                    "network": "private-loopback-only",
                    "filesystem": "tmpfs-with-read-only-tools",
                    "target_mode": "remote-exact-relay" if remote_mode else "local-clone",
                    "pid": server.pid if server is not None else None,
                }
            )
            if not ready:
                return 2
            for raw_line in sys.stdin:
                try:
                    request = json.loads(raw_line)
                    if not isinstance(request, dict):
                        raise ValueError("request must be an object")
                    operation = request.get("op")
                    if operation == "shutdown":
                        _emit({"type": "shutdown", "ok": True})
                        return 0
                    if operation == "inspect":
                        healthy, status = _health()
                        _emit(
                            {
                                "type": "inspection",
                                "server_alive": server.poll() is None if server is not None else None,
                                "health_ok": healthy,
                                "health_status": status,
                                "data_dir": "/arena/data",
                                "legacy_dir": "/opt/legacy",
                            }
                        )
                        continue
                    if operation != "exec":
                        raise ValueError("unsupported operation")
                    _emit(
                        _execute(
                            request.get("command", ""),
                            request.get("timeout_seconds", 20.0),
                            request.get("max_output_bytes", 65_536),
                            server,
                        )
                    )
                except Exception as exc:  # protocol errors are inert and bounded
                    _emit({"type": "protocol_error", "error": type(exc).__name__})
        finally:
            for forwarder in forwarders:
                forwarder.close()
            if server is not None and server.poll() is None:
                try:
                    os.killpg(server.pid, signal.SIGTERM)
                    server.wait(timeout=2)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(server.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
