"""Anthropic Messages API adapter with structured JSON output."""

from __future__ import annotations

from typing import Any, Mapping

from .base import CompletionRequest, ProviderResponseError, parse_strict_json_object, validated_object
from .http_json import JsonEndpointClient


def _messages_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    return base if base.endswith("/v1/messages") else f"{base}/v1/messages"


class AnthropicProvider:
    def __init__(
        self,
        *,
        base_url: str = "https://api.anthropic.com",
        model: str,
        api_key: str | None,
        timeout_seconds: float = 60.0,
    ) -> None:
        if not model.strip():
            raise ValueError("model must be non-empty")
        if not api_key:
            raise ValueError("Anthropic provider requires an API key")
        self.model = model
        self.api_key = api_key
        self.client = JsonEndpointClient(_messages_url(base_url), timeout_seconds=timeout_seconds)
        self.endpoint = self.client.endpoint

    @staticmethod
    def _text(envelope: Mapping[str, Any]) -> str:
        stop = envelope.get("stop_reason")
        if stop in {"refusal", "max_tokens"}:
            raise ProviderResponseError(f"Claude structured output stopped with {stop}")
        for block in envelope.get("content", []):
            if isinstance(block, Mapping) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str):
                    return text
        raise ProviderResponseError("Claude Messages envelope has no text block")

    def complete_json(self, request: CompletionRequest) -> Mapping[str, Any]:
        envelope = self.client.post(
            {
                "model": self.model,
                "max_tokens": max(1_024, min(16_384, request.max_output_chars // 2)),
                "temperature": request.temperature,
                "system": request.system_prompt,
                "messages": [{"role": "user", "content": request.user_prompt}],
                "output_config": {
                    "format": {"type": "json_schema", "schema": request.json_schema}
                },
            },
            {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "User-Agent": "heraclitus-attack/2",
            },
        )
        result = parse_strict_json_object(
            self._text(envelope), max_chars=request.max_output_chars
        )
        return validated_object(result, request.json_schema)


__all__ = ["AnthropicProvider"]
