"""Deterministic provider used by unit tests and offline development."""

from __future__ import annotations

from collections import deque
import json
from typing import Any, Callable, Iterable, Mapping

from .base import (
    CompletionRequest,
    ProviderResponseError,
    parse_strict_json_object,
    validated_object,
)


MockResponse = Mapping[str, Any] | str
MockFactory = Callable[[CompletionRequest, int], MockResponse]


class MockProvider:
    """Return queued or generated results without network access.

    If the queue is empty, the request's deterministic ``fallback_json`` is
    returned.  This makes the entire multi-agent pipeline runnable in CI.
    """

    def __init__(
        self,
        responses: Iterable[MockResponse] = (),
        *,
        factory: MockFactory | None = None,
    ) -> None:
        self._responses = deque(responses)
        self._factory = factory
        self.calls: list[CompletionRequest] = []

    def complete_json(self, request: CompletionRequest) -> Mapping[str, Any]:
        call_index = len(self.calls)
        self.calls.append(request)
        if self._responses:
            response: MockResponse = self._responses.popleft()
        elif self._factory is not None:
            response = self._factory(request, call_index)
        elif request.fallback_json is not None:
            response = request.fallback_json
        else:
            raise ProviderResponseError("MockProvider has no response or fallback")

        if isinstance(response, str):
            obj = parse_strict_json_object(
                response,
                max_chars=request.max_output_chars,
            )
        else:
            encoded = json.dumps(response, ensure_ascii=False)
            if len(encoded) > request.max_output_chars:
                raise ProviderResponseError("mock response exceeds output limit")
            obj = dict(response)
        return validated_object(obj, request.json_schema)

