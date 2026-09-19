import io
import json

import pytest

from heraclitus_attack.console import BootConsole
from heraclitus_attack.models import Verdict


@pytest.mark.parametrize(
    "verdict, phrase",
    [
        (Verdict.PASS, "ataque NÃO funcionou"),
        (Verdict.VULNERABLE, "O BANCO TEM UMA VULNERABILIDADE REPRODUZÍVEL"),
        (Verdict.FAIL, "requer classificação"),
        (Verdict.ERROR, "erro no laboratório"),
        ("skip", "ataque não executado"),
        ("unknown", "não foi possível provar"),
    ],
)
def test_attack_output_is_unambiguous(verdict, phrase):
    output = io.StringIO()
    BootConsole(output, color=False).attack("ATK-01", verdict, "evidence-id=7")
    rendered = output.getvalue()
    assert phrase in rendered
    assert "evidence-id=7" in rendered


def test_color_can_be_forced_but_no_color_wins(monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    output = io.StringIO()
    console = BootConsole(output)
    console.line("PASS", "probe")
    assert "\x1b[" in output.getvalue()

    monkeypatch.setenv("NO_COLOR", "1")
    output = io.StringIO()
    BootConsole(output).line("PASS", "probe")
    assert "\x1b[" not in output.getvalue()


def test_json_stream_is_machine_readable_and_separate():
    human = io.StringIO()
    structured = io.StringIO()
    console = BootConsole(human, color=False, json_stream=structured)
    console.banner("lab", "loopback")
    console.attack("ATK-02", Verdict.PASS)
    console.summary({"PASS": 1}, 0)
    events = [json.loads(line) for line in structured.getvalue().splitlines()]
    assert [event["event"] for event in events] == ["banner", "status", "status", "summary"]
    assert events[1]["status"] == "PASS"
    assert all(event["timestamp"].endswith("+00:00") for event in events)
    assert "timestamp" not in human.getvalue()


def test_summary_uses_vulnerable_or_error_status():
    output = io.StringIO()
    console = BootConsole(output, color=False)
    console.summary({"VULNERABLE": 1}, 2)
    assert "VULNERÁVEL" in output.getvalue()
    output = io.StringIO()
    BootConsole(output, color=False).summary({"ERROR": 1}, 2)
    assert "ERRO" in output.getvalue()

