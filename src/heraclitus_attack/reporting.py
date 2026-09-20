"""Sanitised report artifacts and HeraclitusDB evidence correlation."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping, Sequence

from .coordinator import CampaignReport
from .memory import MemoryEvent, MemoryReceipt, MemorySink
from .models import AttackPlan, Finding, Verdict


@dataclass(frozen=True, slots=True)
class PersistResult:
    receipts: tuple[MemoryReceipt, ...]
    errors: tuple[str, ...]


def _oracle_detail(finding: Finding, key: str) -> Any:
    for result in reversed(finding.oracle_results):
        value = result.details.get(key)
        if value is not None:
            return value
    return None


def memory_event_for(
    plan: AttackPlan,
    finding: Finding,
    *,
    sequence: int,
) -> MemoryEvent:
    target = plan.steps[0].target if plan.steps else "loopback"
    statuses = _oracle_detail(finding, "observed_statuses")
    status = statuses[-1] if isinstance(statuses, list) and statuses else None
    delta = _oracle_detail(finding, "delta")
    expected_statuses = plan.metadata.get("expected_statuses")
    diagnostic_only = plan.metadata.get("diagnostic_only") is True
    denial_invariant = (
        isinstance(expected_statuses, list)
        and bool(expected_statuses)
        and all(isinstance(item, int) and not 200 <= item < 300 for item in expected_statuses)
    )
    return MemoryEvent(
        attack_id=finding.finding_id[:128],
        campaign_id=finding.campaign_id[:128],
        vector=plan.title[:128],
        target=target[:256],
        phase="result",
        result=finding.verdict.value,
        expected=(
            "declared diagnostic property observed"
            if diagnostic_only
            else "attack blocked or declared invariant preserved"
        ),
        reason_code=f"ORACLE_{finding.verdict.value.upper()}",
        blocked=True if finding.verdict is Verdict.PASS and denial_invariant else None,
        upstream_delta=delta if isinstance(delta, int) else None,
        transport_status=status if isinstance(status, int) else None,
        sequence=sequence,
    )


def persist_findings(
    sink: MemorySink,
    plans: Sequence[AttackPlan],
    findings: Sequence[Finding],
) -> PersistResult:
    receipts: list[MemoryReceipt] = []
    errors: list[str] = []
    for sequence, (plan, finding) in enumerate(zip(plans, findings), start=1):
        try:
            receipts.append(
                sink.append(memory_event_for(plan, finding, sequence=sequence))
            )
        except Exception as exc:
            # Do not turn a reporter failure into a false database finding and
            # never include reflected exception text from the HTTP boundary.
            errors.append(f"{finding.finding_id}: {type(exc).__name__}")
    return PersistResult(tuple(receipts), tuple(errors))


def report_document(
    report: CampaignReport,
    *,
    plans: Sequence[AttackPlan],
    persistence: PersistResult | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for index, finding in enumerate(report.findings):
        item = finding.to_dict()
        # Campaign execution is ordered. Titles are intentionally human and
        # may repeat when an agent mutates a curated seed, so they are not a
        # safe correlation key.
        plan = plans[index] if index < len(plans) else None
        if plan is not None and plan.title == finding.title:
            item["plan"] = plan.to_dict()
        findings.append(item)
    document: dict[str, Any] = {
        "schema": "heraclitus-attack-report/v2",
        "campaign_id": report.campaign_id,
        "started_at": report.started_at,
        "duration_ms": report.duration_ms,
        "verdict": report.verdict.value,
        "findings": findings,
    }
    if persistence is not None:
        document["evidence"] = {
            "accepted": sum(1 for receipt in persistence.receipts if receipt.accepted),
            "lsns": [receipt.lsn for receipt in persistence.receipts if receipt.lsn is not None],
            "errors": list(persistence.errors),
        }
    return document


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def write_report(
    report: CampaignReport,
    *,
    plans: Sequence[AttackPlan],
    report_dir: str | Path,
    persistence: PersistResult | None = None,
) -> Path:
    root = Path(report_dir)
    document = report_document(report, plans=plans, persistence=persistence)
    path = root / f"{report.campaign_id}.json"
    _atomic_json(path, document)
    _atomic_json(root / "latest.json", document)
    return path


__all__ = [
    "PersistResult",
    "memory_event_for",
    "persist_findings",
    "report_document",
    "write_report",
]
