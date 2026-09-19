"""Specialised proposal roles for the defensive multi-agent pipeline."""

from __future__ import annotations

from .base import PlanningAgent


class ReconAgent(PlanningAgent):
    role = "recon"
    instruction = (
        "Map only observable local surfaces with low-impact operations. "
        "Prefer read-only health, protocol and capability probes."
    )


class PlannerAgent(PlanningAgent):
    role = "planner"
    instruction = (
        "Turn reconnaissance into one falsifiable security hypothesis. "
        "Declare independent deterministic oracles and explicit expectations."
    )


class CriticAgent(PlanningAgent):
    role = "critic"
    instruction = (
        "Audit the candidate for unsafe reach, weak evidence, false-positive risk "
        "and missing controls, then return a corrected complete plan."
    )


class MutatorAgent(PlanningAgent):
    role = "mutator"
    instruction = (
        "Create one bounded semantic variation that may expose a new edge case. "
        "Do not expand targets, tools, permissions, step budget or risk."
    )


class MinimizerAgent(PlanningAgent):
    role = "minimizer"
    instruction = (
        "Remove redundant steps and payload fields while preserving the exact "
        "hypothesis and independent evidence needed for reproduction."
    )


__all__ = [
    "CriticAgent",
    "MinimizerAgent",
    "MutatorAgent",
    "PlannerAgent",
    "ReconAgent",
]
