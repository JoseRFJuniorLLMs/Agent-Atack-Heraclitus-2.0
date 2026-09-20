"""Role-aware routing across several independent model providers."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Mapping, Sequence

from .base import CompletionRequest, LLMProvider


@dataclass(frozen=True, slots=True)
class ProviderRoute:
    name: str
    provider: LLMProvider
    roles: frozenset[str] = frozenset()


class RoutingProvider:
    """Prefer explicit role assignments, otherwise rotate providers fairly."""

    def __init__(self, routes: Sequence[ProviderRoute]) -> None:
        if not routes:
            raise ValueError("RoutingProvider requires at least one route")
        names = [route.name for route in routes]
        if len(names) != len(set(names)) or any(not name.strip() for name in names):
            raise ValueError("provider route names must be unique and non-empty")
        self.routes = tuple(routes)
        self._counter = 0
        self._lock = Lock()
        self.last_route = ""

    def _select(self, request: CompletionRequest) -> ProviderRoute:
        role = request.metadata.get("role", "")
        explicit = [route for route in self.routes if role in route.roles]
        pool = explicit or list(self.routes)
        with self._lock:
            route = pool[self._counter % len(pool)]
            self._counter += 1
            self.last_route = route.name
        return route

    def complete_json(self, request: CompletionRequest) -> Mapping[str, object]:
        return self._select(request).provider.complete_json(request)


__all__ = ["ProviderRoute", "RoutingProvider"]
