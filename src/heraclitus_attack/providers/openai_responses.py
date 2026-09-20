"""OpenAI Responses API adapter, including Codex-family API models."""

from __future__ import annotations

from typing import Any, Mapping

from .base import CompletionRequest, ProviderResponseError, parse_strict_json_object, validated_object
from .http_json import JsonEndpointClient


def _responses_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    return base if base.endswith("/responses") else f"{base}/responses"


class OpenAIResponsesProvider:
    def __init__(
        self,
        *,
        base_url: str = "https://api.openai.com/v1",
        model: str,
        api_key: str | None,
        timeout_seconds: float = 60.0,
    ) -> None:
        if not model.strip():
            raise ValueError("model must be non-empty")
        if not api_key:
            raise ValueError("OpenAI Responses provider requires an API key")
        self.model = model
        self.api_key = api_key
        self.client = JsonEndpointClient(
            _responses_url(base_url), timeout_seconds=timeout_seconds
        )
        self.endpoint = self.client.endpoint

    @staticmethod
    def _text(envelope: Mapping[str, Any]) -> str:
        direct = envelope.get("output_text")
        if isinstance(direct, str):
            return direct
        for item in envelope.get("output", []):
            if not isinstance(item, Mapping) or item.get("type") != "message":
                continue
            for content in item.get("content", []):
                if isinstance(content, Mapping) and content.get("type") == "output_text":
                    text = content.get("text")
                    if isinstance(text, str):
                        return text
        raise ProviderResponseError("Responses API envelope has no output text")

    def complete_json(self, request: CompletionRequest) -> Mapping[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "instructions": request.system_prompt,
            "input": request.user_prompt,
            "store": False,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": request.schema_name,
                    "strict": True,
                    "schema": request.json_schema,
                }
            },
        }
        if request.temperature != 0:
            payload["temperature"] = request.temperature
        envelope = self.client.post(
            payload,
            {
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "heraclitus-attack/2",
            },
        )
        result = parse_strict_json_object(
            self._text(envelope), max_chars=request.max_output_chars
        )
        return validated_object(result, request.json_schema)


__all__ = ["OpenAIResponsesProvider"]
