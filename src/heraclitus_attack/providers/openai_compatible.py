"""Dependency-free client for a fixed OpenAI-compatible chat endpoint."""

from __future__ import annotations

import json
import ssl
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

from .base import (
    CompletionRequest,
    ProviderError,
    ProviderResponseError,
    parse_strict_json_object,
    validated_object,
)


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ProviderError("model endpoint redirect refused")


def _completion_url(base_url: str) -> str:
    parsed = urlsplit(base_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("provider base_url must be an http(s) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("provider base_url cannot contain credentials/query/fragment")
    if parsed.scheme == "http" and parsed.hostname not in {
        "127.0.0.1",
        "::1",
        "localhost",
    }:
        raise ValueError("plain HTTP model endpoints must be literal loopback")

    path = parsed.path.rstrip("/")
    if path.endswith("/chat/completions"):
        final_path = path
    elif path.endswith("/v1"):
        final_path = f"{path}/chat/completions"
    else:
        final_path = f"{path}/v1/chat/completions"
    return urlunsplit((parsed.scheme, parsed.netloc, final_path, "", ""))


class OpenAICompatibleProvider:
    """Call one immutable endpoint and require a strict JSON-schema response.

    The model is not given tool definitions.  Redirects are refused, response
    bytes are capped, and callers cannot override the URL per completion.
    """

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None = None,
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 1_048_576,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if not model.strip():
            raise ValueError("model must be non-empty")
        if not (0.1 <= timeout_seconds <= 120.0):
            raise ValueError("timeout_seconds outside safe range")
        if not (4_096 <= max_response_bytes <= 4_194_304):
            raise ValueError("max_response_bytes outside safe range")
        self.endpoint = _completion_url(base_url)
        self.model = model
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        handlers: list[Any] = [_NoRedirects()]
        if ssl_context is not None:
            handlers.append(HTTPSHandler(context=ssl_context))
        self._opener = build_opener(*handlers)

    def complete_json(self, request: CompletionRequest) -> Mapping[str, Any]:
        payload = {
            "model": self.model,
            "temperature": request.temperature,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": request.schema_name,
                    "strict": True,
                    "schema": request.json_schema,
                },
            },
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "heraclitus-attack/2",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        wire = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = Request(self.endpoint, data=wire, headers=headers, method="POST")
        try:
            with self._opener.open(req, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_response_bytes + 1)
        except HTTPError as exc:
            # Never include response bodies: compatible gateways sometimes echo
            # secrets or parts of the prompt in errors.
            raise ProviderError(f"model endpoint returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ProviderError("model endpoint is unavailable") from exc
        if len(raw) > self.max_response_bytes:
            raise ProviderResponseError("model endpoint response exceeds byte limit")
        try:
            envelope = json.loads(raw.decode("utf-8"))
            content = envelope["choices"][0]["message"]["content"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise ProviderResponseError("invalid chat completion envelope") from exc
        if not isinstance(content, str):
            raise ProviderResponseError("chat completion content must be a string")
        result = parse_strict_json_object(content, max_chars=request.max_output_chars)
        return validated_object(result, request.json_schema)

