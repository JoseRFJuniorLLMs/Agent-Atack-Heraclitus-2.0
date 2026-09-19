import json
import socket

import pytest

from heraclitus_attack.models import AttackStep, UntrustedData
from heraclitus_attack.tools import (
    HttpRequestTool,
    McpCallTool,
    TcpProbeTool,
    UpstreamCounterTool,
    _body_bytes,
    _headers,
    default_tool_registry,
)


def step(tool="http_request", target="http://127.0.0.1:7475", **arguments):
    return AttackStep(tool=tool, target=target, arguments=arguments)


def test_body_encoding_and_safe_headers():
    assert _body_bytes(None) is None
    assert _body_bytes("abc") == b"abc"
    assert json.loads(_body_bytes({"a": 1})) == {"a": 1}
    assert _headers({"X-Test": "ok"}, "agent")["User-Agent"] == "agent"
    with pytest.raises(ValueError, match="object"):
        _headers(["bad"], "agent")
    with pytest.raises(ValueError, match="override"):
        _headers({"Host": "evil"}, "agent")
    with pytest.raises(ValueError, match="newline"):
        _headers({"X-Test": "ok\r\nInjected: yes"}, "agent")
    with pytest.raises(ValueError, match="too many"):
        _headers({f"X-{n}": "v" for n in range(65)}, "agent")


class FakeResponse:
    status = 200

    def __init__(self, payload=b'{"ok":true}', content_type="application/json"):
        self.payload = payload
        self.content_type = content_type

    def read(self, limit):
        return self.payload[:limit]

    def getheader(self, name):
        assert name == "Content-Type"
        return self.content_type


class FakeConnection:
    response = FakeResponse()
    fail = None
    instances = []

    def __init__(self, host, port, timeout, **kwargs):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.kwargs = kwargs
        self.request_args = None
        self.closed = False
        type(self).instances.append(self)

    def request(self, method, path, body=None, headers=None):
        self.request_args = (method, path, body, headers)
        if type(self).fail:
            raise type(self).fail

    def getresponse(self):
        return type(self).response

    def close(self):
        self.closed = True


def test_http_tool_bounds_response_and_sets_headers(monkeypatch):
    from heraclitus_attack import tools

    FakeConnection.instances.clear()
    FakeConnection.fail = None
    FakeConnection.response = FakeResponse(b"0123456789")
    monkeypatch.setattr(tools.http.client, "HTTPConnection", FakeConnection)
    observed = HttpRequestTool().execute(
        step(method="POST", path="/events", body={"x": 1}),
        timeout_seconds=2,
        max_response_bytes=5,
        user_agent="tester",
    )
    assert observed.ok
    assert observed.status_code == 200
    assert observed.untrusted_response.text == "01234"
    assert observed.untrusted_response.truncated
    assert observed.evidence["response_bytes_observed"] == 6
    connection = FakeConnection.instances[-1]
    method, path, body, headers = connection.request_args
    assert (method, path) == ("POST", "/events")
    assert json.loads(body) == {"x": 1}
    assert headers["Content-Length"] == str(len(body))
    assert connection.closed


def test_http_tool_reports_sanitised_error_and_closes(monkeypatch):
    from heraclitus_attack import tools

    FakeConnection.instances.clear()
    FakeConnection.fail = OSError("secret target details")
    monkeypatch.setattr(tools.http.client, "HTTPConnection", FakeConnection)
    observed = HttpRequestTool().execute(
        step(), timeout_seconds=1, max_response_bytes=50, user_agent="tester"
    )
    assert not observed.ok
    assert observed.error == "OSError during loopback tool execution"
    assert "secret" not in observed.error
    assert FakeConnection.instances[-1].closed
    FakeConnection.fail = None


def test_mcp_tool_builds_json_rpc_post(monkeypatch):
    captured = {}

    def fake_execute(self, delegated, **kwargs):
        captured["step"] = delegated
        return "observed"

    monkeypatch.setattr(HttpRequestTool, "execute", fake_execute)
    result = McpCallTool().execute(
        step(tool="mcp_call", message={"jsonrpc": "2.0"}),
        timeout_seconds=1,
        max_response_bytes=50,
        user_agent="tester",
    )
    assert result == "observed"
    delegated = captured["step"]
    assert delegated.arguments["method"] == "POST"
    assert delegated.arguments["path"] == "/mcp"
    assert delegated.arguments["body"] == {"jsonrpc": "2.0"}


class DummySocket:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_tcp_probe_success_and_failure(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: DummySocket())
    probe = TcpProbeTool().execute(
        step(tool="tcp_probe", target="127.0.0.1:7474"),
        timeout_seconds=1,
        max_response_bytes=1,
        user_agent="x",
    )
    assert probe.ok and probe.evidence["reachable"] is True

    def fail(*args, **kwargs):
        raise OSError("sensitive")

    monkeypatch.setattr(socket, "create_connection", fail)
    probe = TcpProbeTool().execute(
        step(tool="tcp_probe", target="127.0.0.1:7474"),
        timeout_seconds=1,
        max_response_bytes=1,
        user_agent="x",
    )
    assert not probe.ok and probe.evidence["reachable"] is False
    assert "sensitive" not in probe.error


def observed_with_body(body, *, ok=True):
    from heraclitus_attack.models import Observation

    return Observation(
        step_id="s",
        tool="upstream_counter",
        target="http://127.0.0.1:19000",
        started_at="now",
        duration_ms=1,
        ok=ok,
        status_code=200,
        untrusted_response=UntrustedData.from_bytes(body),
        evidence={"method": "GET"},
    )


@pytest.mark.parametrize(
    "body, expected, ok",
    [
        (b'{"hits":7}', 7, True),
        (b'{"hits":true}', None, False),
        (b'{"hits":-1}', None, False),
        (b"not json", None, False),
    ],
)
def test_upstream_counter_requires_a_non_negative_integer(monkeypatch, body, expected, ok):
    monkeypatch.setattr(HttpRequestTool, "execute", lambda *args, **kwargs: observed_with_body(body))
    result = UpstreamCounterTool().execute(
        step(tool="upstream_counter"),
        timeout_seconds=1,
        max_response_bytes=100,
        user_agent="tester",
    )
    assert result.evidence["counter"] == expected
    assert result.ok is ok


def test_default_registry_has_only_fixed_adapters():
    registry = default_tool_registry()
    assert set(registry) == {"http_request", "mcp_call", "tcp_probe", "upstream_counter"}
    assert "shell" not in registry
    assert "subprocess" not in registry

