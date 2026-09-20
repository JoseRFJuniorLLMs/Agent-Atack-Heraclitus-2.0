"""Shared fixed-endpoint JSON transport for model providers."""

from __future__ import annotations

import json
import ssl
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .base import ProviderError, ProviderResponseError


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ProviderError("model endpoint redirect refused")


def validate_endpoint(endpoint: str) -> str:
    parsed = urlsplit(endpoint.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("provider endpoint must be an http(s) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("provider endpoint cannot contain credentials or a fragment")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("plain HTTP provider endpoints must be literal loopback")
    return endpoint.rstrip("/")


class JsonEndpointClient:
    def __init__(
        self,
        endpoint: str,
        *,
        timeout_seconds: float,
        max_response_bytes: int = 1_048_576,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.endpoint = validate_endpoint(endpoint)
        if not 0.1 <= timeout_seconds <= 120:
            raise ValueError("timeout_seconds outside safe range")
        if not 4_096 <= max_response_bytes <= 4_194_304:
            raise ValueError("max_response_bytes outside safe range")
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        handlers: list[Any] = [NoRedirects()]
        if ssl_context is not None:
            handlers.append(HTTPSHandler(context=ssl_context))
        self._opener = build_opener(*handlers)

    def post(self, payload: Mapping[str, Any], headers: Mapping[str, str]) -> dict[str, Any]:
        wire = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = Request(
            self.endpoint,
            data=wire,
            headers={"Accept": "application/json", "Content-Type": "application/json", **headers},
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_response_bytes + 1)
        except HTTPError as exc:
            raise ProviderError(f"model endpoint returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ProviderError("model endpoint is unavailable") from exc
        if len(raw) > self.max_response_bytes:
            raise ProviderResponseError("model endpoint response exceeds byte limit")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderResponseError("model endpoint returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise ProviderResponseError("model endpoint response must be an object")
        return value


__all__ = ["JsonEndpointClient", "NoRedirects", "validate_endpoint"]
