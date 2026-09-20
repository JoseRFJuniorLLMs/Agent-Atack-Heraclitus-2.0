"""Trusted credential injection that never exposes secrets to an AttackPlan."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import os
from typing import Mapping

from .models import AttackStep, Observation
from .safety import canonical_target
from .tools import ToolAdapter, default_tool_registry


@dataclass(frozen=True, slots=True)
class TrustedHeaderAdapter:
    """Add headers only after safety validation and only for an exact origin.

    LLM-generated plans cannot contain credentials.  This adapter owns a fixed
    origin-to-header mapping assembled by trusted application configuration.
    """

    inner: ToolAdapter
    headers_by_origin: Mapping[str, Mapping[str, str]]

    def __post_init__(self) -> None:
        if not callable(getattr(self.inner, "execute_with_trusted_headers", None)):
            raise TypeError("inner adapter does not support trusted headers")

    def execute(
        self,
        step: AttackStep,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        user_agent: str,
    ) -> Observation:
        trusted = self.headers_by_origin.get(canonical_target(step.target), {})
        if not trusted:
            return self.inner.execute(
                step,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
                user_agent=user_agent,
            )
        # The secret travels on a separate trusted call path; it never becomes
        # part of the plan or passes through the untrusted-header parser.
        return self.inner.execute_with_trusted_headers(  # type: ignore[attr-defined]
            step,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            user_agent=user_agent,
            trusted_headers=trusted,
        )


def trusted_headers(
    *,
    core_rest: str,
    agent_api: str,
    mcp_gateway: str,
    environ: Mapping[str, str] | None = None,
) -> dict[str, dict[str, str]]:
    env = environ if environ is not None else os.environ
    result: dict[str, dict[str, str]] = {}
    username = env.get("HERACLITUS_CORE_USERNAME", "").strip()
    password = env.get("HERACLITUS_CORE_PASSWORD", "")
    if username and password:
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        result[canonical_target(core_rest)] = {"Authorization": f"Basic {encoded}"}
    token = env.get("HERACLITUS_AGENT_TOKEN", "").strip()
    if token:
        header = {"Authorization": f"Bearer {token}"}
        result[canonical_target(agent_api)] = header
        result[canonical_target(mcp_gateway)] = header
    return result


def authenticated_tool_registry(
    *,
    core_rest: str,
    agent_api: str,
    mcp_gateway: str,
    environ: Mapping[str, str] | None = None,
) -> dict[str, ToolAdapter]:
    registry = default_tool_registry()
    headers = trusted_headers(
        core_rest=core_rest,
        agent_api=agent_api,
        mcp_gateway=mcp_gateway,
        environ=environ,
    )
    if headers:
        for name in ("http_request", "mcp_call"):
            registry[name] = TrustedHeaderAdapter(registry[name], headers)
    return registry


__all__ = ["TrustedHeaderAdapter", "authenticated_tool_registry", "trusted_headers"]
