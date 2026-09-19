"""Independent, deterministic oracles for adversarial observations.

The model may propose a plan, but it never decides whether that plan exposed a
vulnerability.  These oracles fail closed when evidence is absent or ambiguous.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .models import AttackPlan, Observation, OracleResult, Verdict


class Oracle(Protocol):
    oracle_id: str

    def evaluate(
        self, plan: AttackPlan, observations: Sequence[Observation]
    ) -> OracleResult: ...


def _fingerprint(value: Any) -> str:
    wire = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()
    return hashlib.sha256(wire).hexdigest()


def _result(
    oracle_id: str,
    verdict: Verdict,
    reason: str,
    *,
    evidence: Any = None,
    details: Mapping[str, Any] | None = None,
) -> OracleResult:
    return OracleResult(
        oracle_id=oracle_id,
        verdict=verdict,
        reason=reason,
        evidence_fingerprint=_fingerprint(evidence) if evidence is not None else None,
        details=details or {},
    )


@dataclass(frozen=True, slots=True)
class HttpStatusOracle:
    """Compare HTTP statuses with an explicit expectation in plan metadata."""

    oracle_id: str = "http_status"

    def evaluate(
        self, plan: AttackPlan, observations: Sequence[Observation]
    ) -> OracleResult:
        raw = plan.metadata.get("expected_statuses")
        if not isinstance(raw, list) or not raw:
            return _result(
                self.oracle_id,
                Verdict.INCONCLUSIVE,
                "plano não declarou expected_statuses",
            )
        try:
            expected = {int(item) for item in raw}
        except (TypeError, ValueError):
            return _result(
                self.oracle_id,
                Verdict.ERROR,
                "expected_statuses inválido",
            )
        raw_tools = plan.metadata.get("status_tools")
        status_tools = (
            {str(item) for item in raw_tools}
            if isinstance(raw_tools, list) and raw_tools
            else None
        )
        http = [
            item
            for item in observations
            if item.status_code is not None
            and (status_tools is None or item.tool in status_tools)
        ]
        if not http:
            return _result(
                self.oracle_id,
                Verdict.INCONCLUSIVE,
                "nenhuma resposta HTTP observável",
            )
        seen = [int(item.status_code) for item in http if item.status_code is not None]
        raw_inconclusive = plan.metadata.get("inconclusive_statuses", [])
        try:
            inconclusive = {int(item) for item in raw_inconclusive}
        except (TypeError, ValueError):
            return _result(
                self.oracle_id,
                Verdict.ERROR,
                "inconclusive_statuses inválido",
            )
        if any(status in inconclusive for status in seen):
            return _result(
                self.oracle_id,
                Verdict.INCONCLUSIVE,
                "autenticação ou pré-requisito impediu exercitar o invariante",
                evidence=seen,
                details={"observed_statuses": seen},
            )
        unexpected = [status for status in seen if status not in expected]
        if not unexpected:
            return _result(
                self.oracle_id,
                Verdict.PASS,
                "todos os status HTTP satisfizeram o invariante",
                evidence=seen,
                details={"observed_statuses": seen},
            )
        verdict = (
            Verdict.VULNERABLE
            if plan.metadata.get("unexpected_status_is_vulnerability") is True
            else Verdict.FAIL
        )
        return _result(
            self.oracle_id,
            verdict,
            "status HTTP explícito violou o invariante",
            evidence=seen,
            details={"observed_statuses": seen, "unexpected_count": len(unexpected)},
        )


@dataclass(frozen=True, slots=True)
class AvailabilityOracle:
    """Check that a probe did not make the target unavailable."""

    oracle_id: str = "availability"

    def evaluate(
        self, plan: AttackPlan, observations: Sequence[Observation]
    ) -> OracleResult:
        del plan
        health = [item for item in observations if "health" in item.evidence]
        if not health:
            return _result(
                self.oracle_id,
                Verdict.INCONCLUSIVE,
                "plano não coletou health independente após o ataque",
            )
        values = [bool(item.evidence.get("health")) for item in health]
        verdict = Verdict.PASS if all(values) else Verdict.VULNERABLE
        reason = (
            "health pós-ataque permaneceu disponível"
            if verdict is Verdict.PASS
            else "health independente falhou após o ataque"
        )
        return _result(self.oracle_id, verdict, reason, evidence=values)


@dataclass(frozen=True, slots=True)
class ReachabilityOracle:
    """Report listener reachability without claiming that TCP proves health."""

    oracle_id: str = "reachability"

    def evaluate(
        self, plan: AttackPlan, observations: Sequence[Observation]
    ) -> OracleResult:
        del plan
        probes = [
            item.evidence.get("reachable")
            for item in observations
            if isinstance(item.evidence.get("reachable"), bool)
        ]
        if not probes:
            return _result(
                self.oracle_id,
                Verdict.INCONCLUSIVE,
                "nenhum probe TCP tipado foi observado",
            )
        if all(probes):
            return _result(
                self.oracle_id,
                Verdict.PASS,
                "listener loopback está alcançável (isto não prova health gRPC)",
                evidence=probes,
            )
        return _result(
            self.oracle_id,
            Verdict.INCONCLUSIVE,
            "listener indisponível; ataque não foi exercitado",
            evidence=probes,
        )


@dataclass(frozen=True, slots=True)
class UpstreamEffectOracle:
    """Prove that a denied action did not reach the synthetic upstream."""

    oracle_id: str = "upstream_zero"

    @staticmethod
    def _counter(observation: Observation) -> int | None:
        for key in ("counter", "upstream_count", "hits"):
            value = observation.evidence.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                return value
        return None

    def evaluate(
        self, plan: AttackPlan, observations: Sequence[Observation]
    ) -> OracleResult:
        del plan
        counters = [value for item in observations if (value := self._counter(item)) is not None]
        if len(counters) < 2:
            return _result(
                self.oracle_id,
                Verdict.INCONCLUSIVE,
                "contador upstream antes/depois não foi observado",
            )
        delta = counters[-1] - counters[0]
        if delta < 0:
            return _result(
                self.oracle_id,
                Verdict.INCONCLUSIVE,
                "contador upstream regrediu ou foi reiniciado",
                evidence=counters,
                details={"delta": delta},
            )
        verdict = Verdict.PASS if delta == 0 else Verdict.VULNERABLE
        reason = (
            "nenhum efeito externo foi observado"
            if delta == 0
            else "ação negada alcançou o upstream sintético"
        )
        return _result(
            self.oracle_id,
            verdict,
            reason,
            # Reproduction compares fingerprints across attempts.  Absolute
            # counters naturally advance, while the violated invariant is the
            # stable delta itself.
            evidence={"delta": delta},
            details={"delta": delta},
        )


@dataclass(frozen=True, slots=True)
class SensitiveLeakOracle:
    """Search raw responses for operator-provided canaries, never for secrets."""

    oracle_id: str = "no_sensitive_leak"

    def evaluate(
        self, plan: AttackPlan, observations: Sequence[Observation]
    ) -> OracleResult:
        raw_markers = plan.metadata.get("forbidden_markers")
        if not isinstance(raw_markers, list) or not raw_markers:
            return _result(
                self.oracle_id,
                Verdict.INCONCLUSIVE,
                "nenhum canário sintético foi configurado",
            )
        markers = [str(item) for item in raw_markers if str(item)]
        bodies = [
            item.untrusted_response.text
            for item in observations
            if item.untrusted_response is not None
        ]
        if not bodies:
            return _result(
                self.oracle_id,
                Verdict.INCONCLUSIVE,
                "nenhum corpo de resposta foi capturado",
            )
        matches = sum(marker in body for marker in markers for body in bodies)
        verdict = Verdict.VULNERABLE if matches else Verdict.PASS
        reason = (
            "resposta expôs canário sintético proibido"
            if matches
            else "nenhum canário sintético apareceu nas respostas"
        )
        return _result(
            self.oracle_id,
            verdict,
            reason,
            # Do not require byte-identical responses across reproductions;
            # the stable security fact is whether a canary leaked.
            evidence={"marker_leaked": bool(matches)},
            details={"match_count": matches},
        )


@dataclass(frozen=True, slots=True)
class EvidenceReceiptOracle:
    """Require a native or red-team evidence identity/LSN for correlation."""

    oracle_id: str = "evidence_receipt"

    def evaluate(
        self, plan: AttackPlan, observations: Sequence[Observation]
    ) -> OracleResult:
        del plan
        receipts: list[str] = []
        for observation in observations:
            for key in ("lsn", "evidence_lsn", "evidence_id"):
                value = observation.evidence.get(key)
                if isinstance(value, (str, int)) and str(value):
                    receipts.append(str(value))
        if not receipts:
            return _result(
                self.oracle_id,
                Verdict.INCONCLUSIVE,
                "nenhum recibo de evidência nativa foi correlacionado",
            )
        return _result(
            self.oracle_id,
            Verdict.PASS,
            "recibo de evidência foi correlacionado",
            evidence=receipts,
            details={"receipt_count": len(receipts)},
        )


class OracleRegistry:
    """Resolve only pre-registered deterministic oracles."""

    def __init__(self, oracles: Iterable[Oracle] | None = None) -> None:
        provided = tuple(oracles or default_oracles())
        self._oracles = {item.oracle_id: item for item in provided}
        if len(self._oracles) != len(provided):
            raise ValueError("oracle IDs must be unique")

    def resolve(self, oracle_id: str) -> Oracle:
        try:
            return self._oracles[oracle_id]
        except KeyError as exc:
            raise KeyError(f"oracle is not registered: {oracle_id!r}") from exc

    def evaluate(
        self, plan: AttackPlan, observations: Sequence[Observation]
    ) -> tuple[OracleResult, ...]:
        return tuple(self.resolve(name).evaluate(plan, observations) for name in plan.oracle_ids)

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._oracles))


def default_oracles() -> tuple[Oracle, ...]:
    return (
        HttpStatusOracle(),
        AvailabilityOracle(),
        ReachabilityOracle(),
        UpstreamEffectOracle(),
        SensitiveLeakOracle(),
        EvidenceReceiptOracle(),
    )
