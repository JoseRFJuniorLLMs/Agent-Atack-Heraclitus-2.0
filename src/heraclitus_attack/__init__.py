"""Safe, loopback-only agentic security qualification for HeraclitusDB."""

from .config import AppConfig, BudgetConfig, RuntimeConfig, SafetyConfig
from .coordinator import (
    CampaignReport,
    Coordinator,
    Oracle,
    PlanningContext,
    PlanProposer,
)
from .executor import ExecutionBudgetExceeded, SafeToolExecutor
from .models import (
    AttackPlan,
    AttackStep,
    Finding,
    Observation,
    OracleResult,
    RiskLevel,
    UntrustedData,
    Verdict,
    new_id,
)
from .safety import (
    canonical_target,
    DestructiveAuthorization,
    SafetyGate,
    SafetyViolation,
    is_loopback_host,
    validate_loopback_target,
)

__all__ = [
    "AppConfig",
    "AttackPlan",
    "AttackStep",
    "BudgetConfig",
    "CampaignReport",
    "canonical_target",
    "Coordinator",
    "DestructiveAuthorization",
    "ExecutionBudgetExceeded",
    "Finding",
    "Observation",
    "Oracle",
    "OracleResult",
    "PlanningContext",
    "PlanProposer",
    "RiskLevel",
    "RuntimeConfig",
    "SafeToolExecutor",
    "SafetyConfig",
    "SafetyGate",
    "SafetyViolation",
    "UntrustedData",
    "Verdict",
    "is_loopback_host",
    "new_id",
    "validate_loopback_target",
]

__version__ = "2.0.0"
