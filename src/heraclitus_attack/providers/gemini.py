"""Google Gemini generateContent adapter with JSON Schema output."""

from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import quote

from .base import CompletionRequest, ProviderResponseError, parse_strict_json_object, validated_object
from .http_json import JsonEndpointClient


def _generate_url(base_url: str, model: str) -> str:
    clean = model.removeprefix("models/").strip()
    if not clean or not re.fullmatch(r"[A-Za-z0-9._-]+", clean):
        raise ValueError("Gemini model name contains unsupported characters")
    base = base_url.rstrip("/")
    return f"{base}/models/{quote(clean, safe='._-')}:generateContent"


class GeminiProvider:
    def __init__(
        self,
        *,
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
        model: str,
        api_key: str | None,
        timeout_seconds: float = 60.0,
    ) -> None:
        if not api_key:
            raise ValueError("Gemini provider requires an API key")
        self.model = model
        self.api_key = api_key
        self.client = JsonEndpointClient(
            _generate_url(base_url, model), timeout_seconds=timeout_seconds
        )
        self.endpoint = self.client.endpoint

    @staticmethod
    def _text(envelope: Mapping[str, Any]) -> str:
        try:
            candidates = envelope["candidates"]
            first = candidates[0]
            parts = first["content"]["parts"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderResponseError("Gemini envelope has no candidate content") from exc
        text = "".join(
            str(part.get("text", ""))
            for part in parts
            if isinstance(part, Mapping) and isinstance(part.get("text"), str)
        )
        if not text:
            raise ProviderResponseError("Gemini envelope has no text part")
        return text

    def complete_json(self, request: CompletionRequest) -> Mapping[str, Any]:
        envelope = self.client.post(
            {
                "systemInstruction": {"parts": [{"text": request.system_prompt}]},
                "contents": [
                    {"role": "user", "parts": [{"text": request.user_prompt}]}
                ],
                "generationConfig": {
                    "temperature": request.temperature,
                    "responseMimeType": "application/json",
                    "responseJsonSchema": request.json_schema,
                },
            },
            {
                "x-goog-api-key": self.api_key,
                "User-Agent": "heraclitus-attack/2",
            },
        )
        result = parse_strict_json_object(
            self._text(envelope), max_chars=request.max_output_chars
        )
        return validated_object(result, request.json_schema)


__all__ = ["GeminiProvider"]
