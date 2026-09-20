"""Saida legivel no estilo do boot do Fedora, com semantica inequívoca."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TextIO


class BootConsole:
    """Renderiza progresso humano e, opcionalmente, eventos JSON para automacao."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    COLORS = {
        "PASS": "\033[1;32m",
        "VULNERABLE": "\033[1;31m",
        "FAIL": "\033[1;31m",
        "ERROR": "\033[1;35m",
        "INCONCLUSIVE": "\033[1;33m",
        "SKIP": "\033[1;33m",
        "RUN": "\033[1;36m",
        "INFO": "\033[1;34m",
    }
    LABELS = {
        "PASS": "   OK   ",
        "VULNERABLE": "VULNERÁVEL",
        "FAIL": " FALHA  ",
        "ERROR": "  ERRO  ",
        "INCONCLUSIVE": " INCERTO ",
        "SKIP": " PULOU  ",
        "RUN": "RODANDO ",
        "INFO": "  INFO  ",
    }

    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        color: bool | None = None,
        json_stream: TextIO | None = None,
    ) -> None:
        self.stream = stream or sys.stdout
        self.json_stream = json_stream
        if color is None:
            forced = os.getenv("FORCE_COLOR", "").casefold() in {"1", "true", "yes"}
            systemd = os.getenv("SYSTEMD_COLORS", "").casefold() in {"1", "true", "yes"}
            tty = bool(getattr(self.stream, "isatty", lambda: False)())
            color = os.getenv("NO_COLOR") is None and (forced or systemd or tty)
        self.color = color

    @staticmethod
    def _status(value: Any) -> str:
        if isinstance(value, Enum):
            value = value.value
        return str(value).upper()

    def _paint(self, text: str, status: str) -> str:
        if not self.color:
            return text
        return f"{self.COLORS.get(status, '')}{text}{self.RESET}"

    def _json_event(self, event: str, **fields: Any) -> None:
        if self.json_stream is None:
            return
        safe: dict[str, Any] = {}
        for key, value in fields.items():
            if isinstance(value, Enum):
                value = value.value
            elif is_dataclass(value) and not isinstance(value, type):
                value = asdict(value)
            safe[key] = value
        safe.update(
            event=event,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        print(json.dumps(safe, ensure_ascii=False, default=str), file=self.json_stream, flush=True)

    def banner(self, title: str, subtitle: str = "") -> None:
        width = 80
        print(self._paint("=" * width, "INFO"), file=self.stream)
        print(self._paint(f"  {title}", "INFO"), file=self.stream)
        if subtitle:
            print(f"  {subtitle}", file=self.stream)
        print(self._paint("=" * width, "INFO"), file=self.stream, flush=True)
        self._json_event("banner", title=title, subtitle=subtitle)

    def line(self, status: Any, name: str, detail: str = "") -> None:
        normalized = self._status(status)
        label = self.LABELS.get(normalized, normalized[:10].center(10))
        left = self._paint(f"[ {label} ]", normalized)
        suffix = f" — {detail}" if detail else ""
        print(f"{left} {name}{suffix}", file=self.stream, flush=True)
        self._json_event("status", status=normalized, name=name, detail=detail)

    def attack(
        self,
        name: str,
        verdict: Any,
        detail: str = "",
        *,
        diagnostic: bool = False,
    ) -> None:
        """Mostra o significado operacional; nunca chama erro do harness de falha do DB."""

        normalized = self._status(verdict)
        if diagnostic and normalized == "PASS":
            message = "diagnóstico concluído; a propriedade declarada foi observada"
        elif normalized == "PASS":
            message = "ataque NÃO funcionou; a proteção foi comprovada pelo oráculo"
        elif normalized == "VULNERABLE":
            message = "ATAQUE FUNCIONOU — O BANCO TEM UMA VULNERABILIDADE REPRODUZÍVEL"
        elif normalized == "FAIL":
            message = "a propriedade esperada falhou; requer classificação antes de afirmar vulnerabilidade"
        elif normalized == "ERROR":
            message = "erro no laboratório; nenhum diagnóstico de vulnerabilidade foi emitido"
        elif normalized == "SKIP":
            message = "ataque não executado; pré-requisito ausente"
        else:
            normalized = "INCONCLUSIVE"
            message = "não foi possível provar se o ataque funcionou"
        if detail:
            message = f"{message}; {detail}"
        self.line(normalized, name, message)

    def summary(self, counts: dict[str, int], exit_code: int) -> None:
        ordered = " · ".join(f"{key}={value}" for key, value in sorted(counts.items()))
        if counts.get("VULNERABLE"):
            status = "VULNERABLE"
        elif counts.get("ERROR") or exit_code >= 4:
            status = "ERROR"
        elif counts.get("FAIL"):
            status = "FAIL"
        elif counts.get("INCONCLUSIVE") or exit_code:
            status = "INCONCLUSIVE"
        else:
            status = "PASS"
        self.line(status, "campanha concluída", f"{ordered}; exit={exit_code}")
        self._json_event("summary", counts=counts, exit_code=exit_code)
