import io
import json
from urllib.error import HTTPError, URLError

import pytest

from heraclitus_attack.providers import (
    AnthropicProvider,
    CompletionRequest,
    GeminiProvider,
    MockProvider,
    OpenAICompatibleProvider,
    OpenAIResponsesProvider,
    ProviderRoute,
    ProviderError,
    ProviderResponseError,
    RoutingProvider,
    parse_strict_json_object,
    validate_json_schema,
    validated_object,
)
from heraclitus_attack.providers.openai_compatible import _completion_url


SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["name", "steps"],
    "properties": {
        "name": {"type": "string", "minLength": 1, "maxLength": 8},
        "steps": {
            "type": "array",
            "minItems": 1,
            "maxItems": 2,
            "items": {"type": "integer"},
        },
        "enabled": {"type": "boolean"},
        "mode": {"type": "string", "enum": ["safe"]},
    },
}


def request(**overrides):
    values = {
        "system_prompt": "Return strict JSON.",
        "user_prompt": "Create one bounded plan.",
        "json_schema": SCHEMA,
        "fallback_json": {"name": "probe", "steps": [1]},
    }
    values.update(overrides)
    return CompletionRequest(**values)


def test_completion_request_validates_prompts_temperature_and_limit():
    with pytest.raises(ValueError, match="non-empty"):
        request(system_prompt=" ")
    with pytest.raises(ValueError, match="temperature"):
        request(temperature=2.1)
    with pytest.raises(ValueError, match="safe range"):
        request(max_output_chars=100)


def test_strict_json_parser_refuses_prose_arrays_and_large_output():
    assert parse_strict_json_object('{"ok":true}', max_chars=100) == {"ok": True}
    with pytest.raises(ProviderResponseError, match="strict JSON"):
        parse_strict_json_object("```json\n{}\n```", max_chars=100)
    with pytest.raises(ProviderResponseError, match="one JSON object"):
        parse_strict_json_object("[]", max_chars=100)
    with pytest.raises(ProviderResponseError, match="exceeds"):
        parse_strict_json_object('{"long":"value"}', max_chars=4)


@pytest.mark.parametrize(
    "value, message",
    [
        ({"steps": [1]}, "missing required"),
        ({"name": "probe", "steps": [1], "extra": True}, "unexpected field"),
        ({"name": "", "steps": [1]}, "string length"),
        ({"name": "probe", "steps": []}, "array length"),
        ({"name": "probe", "steps": [True]}, "expected integer"),
        ({"name": "probe", "steps": [1], "enabled": 1}, "expected boolean"),
        ({"name": "probe", "steps": [1], "mode": "unsafe"}, "allowed enum"),
    ],
)
def test_schema_validation_rejects_invalid_structures(value, message):
    with pytest.raises(ProviderResponseError, match=message):
        validate_json_schema(value, SCHEMA)


def test_schema_validation_supports_type_unions_and_detaches_result():
    validate_json_schema(None, {"type": ["string", "null"]})
    value = {"name": "probe", "steps": [1]}
    copied = validated_object(value, SCHEMA)
    value["steps"].append(2)
    assert copied["steps"] == [1]
    with pytest.raises(ProviderResponseError, match="serializable"):
        validated_object({"bad": object()}, {})


def test_mock_provider_queue_factory_and_fallback_are_deterministic():
    provider = MockProvider([{"name": "one", "steps": [1]}])
    assert provider.complete_json(request())["name"] == "one"
    assert provider.complete_json(request())["name"] == "probe"
    assert len(provider.calls) == 2

    generated = MockProvider(factory=lambda req, index: {"name": f"p{index}", "steps": [1]})
    assert generated.complete_json(request())["name"] == "p0"


def test_mock_provider_parses_strings_and_rejects_missing_or_large_results():
    assert MockProvider(['{"name":"ok","steps":[1]}']).complete_json(request())["name"] == "ok"
    with pytest.raises(ProviderResponseError, match="no response"):
        MockProvider().complete_json(request(fallback_json=None))
    with pytest.raises(ProviderResponseError, match="output limit"):
        MockProvider([{"name": "x" * 300, "steps": [1]}]).complete_json(
            request(max_output_chars=256)
        )


@pytest.mark.parametrize(
    "base, expected",
    [
        ("http://127.0.0.1:11434", "http://127.0.0.1:11434/v1/chat/completions"),
        ("https://models.example/v1", "https://models.example/v1/chat/completions"),
        ("https://models.example/chat/completions", "https://models.example/chat/completions"),
    ],
)
def test_completion_url_is_fixed(base, expected):
    assert _completion_url(base) == expected


@pytest.mark.parametrize(
    "base",
    [
        "ftp://127.0.0.1/model",
        "http://models.example/v1",
        "https://user:secret@models.example/v1",
        "https://models.example/v1?q=x",
    ],
)
def test_completion_url_rejects_unsafe_forms(base):
    with pytest.raises(ValueError):
        _completion_url(base)


def test_provider_constructor_bounds():
    with pytest.raises(ValueError, match="model"):
        OpenAICompatibleProvider(base_url="http://127.0.0.1", model=" ")
    with pytest.raises(ValueError, match="timeout"):
        OpenAICompatibleProvider(base_url="http://127.0.0.1", model="m", timeout_seconds=0)
    with pytest.raises(ValueError, match="max_response"):
        OpenAICompatibleProvider(base_url="http://127.0.0.1", model="m", max_response_bytes=100)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, _limit):
        return self.payload


class FakeOpener:
    def __init__(self, result):
        self.result = result
        self.seen = None

    def open(self, req, timeout):
        self.seen = (req, timeout)
        if isinstance(self.result, BaseException):
            raise self.result
        return FakeResponse(self.result)


def test_openai_compatible_provider_validates_envelope_and_schema():
    content = json.dumps({"name": "probe", "steps": [1]})
    envelope = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
    provider = OpenAICompatibleProvider(
        base_url="http://127.0.0.1:11434/v1", model="local", api_key="token"
    )
    provider._opener = FakeOpener(envelope)
    assert provider.complete_json(request()) == {"name": "probe", "steps": [1]}
    req, timeout = provider._opener.seen
    assert timeout == 30.0
    assert req.get_header("Authorization") == "Bearer token"
    sent = json.loads(req.data)
    assert sent["response_format"]["json_schema"]["strict"] is True


@pytest.mark.parametrize(
    "payload, message",
    [
        (b"not-json", "invalid chat completion envelope"),
        (b'{"choices":[]}', "invalid chat completion envelope"),
        (b'{"choices":[{"message":{"content":42}}]}', "content must be a string"),
    ],
)
def test_openai_provider_rejects_bad_envelopes(payload, message):
    provider = OpenAICompatibleProvider(base_url="http://127.0.0.1", model="local")
    provider._opener = FakeOpener(payload)
    with pytest.raises(ProviderResponseError, match=message):
        provider.complete_json(request())


def test_openai_provider_sanitises_transport_failures():
    provider = OpenAICompatibleProvider(base_url="http://127.0.0.1", model="local")
    provider._opener = FakeOpener(URLError("secret reflected body"))
    with pytest.raises(ProviderError, match="unavailable") as caught:
        provider.complete_json(request())
    assert "secret" not in str(caught.value)

    error = HTTPError(provider.endpoint, 429, "rate", {}, io.BytesIO(b"secret"))
    provider._opener = FakeOpener(error)
    with pytest.raises(ProviderError, match="HTTP 429") as caught:
        provider.complete_json(request())
    assert "secret" not in str(caught.value)


def test_openai_provider_caps_response_bytes():
    provider = OpenAICompatibleProvider(
        base_url="http://127.0.0.1", model="local", max_response_bytes=4096
    )
    provider._opener = FakeOpener(b"x" * 4097)
    with pytest.raises(ProviderResponseError, match="byte limit"):
        provider.complete_json(request())


class CapturingJsonClient:
    def __init__(self, response):
        self.response = response
        self.seen = None

    def post(self, payload, headers):
        self.seen = (payload, headers)
        return self.response


def test_openai_responses_provider_extracts_structured_output():
    content = json.dumps({"name": "codex", "steps": [1]})
    provider = OpenAIResponsesProvider(
        base_url="https://api.openai.com/v1",
        model="gpt-codex-test",
        api_key="key",
    )
    provider.client = CapturingJsonClient(
        {
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": content}],
                }
            ]
        }
    )
    assert provider.complete_json(request())["name"] == "codex"
    payload, headers = provider.client.seen
    assert payload["text"]["format"]["type"] == "json_schema"
    assert payload["store"] is False
    assert headers["Authorization"] == "Bearer key"


def test_anthropic_provider_uses_output_config_and_handles_refusal():
    provider = AnthropicProvider(
        base_url="https://api.anthropic.com",
        model="claude-test",
        api_key="key",
    )
    provider.client = CapturingJsonClient(
        {
            "stop_reason": "end_turn",
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({"name": "claude", "steps": [1]}),
                }
            ],
        }
    )
    assert provider.complete_json(request())["name"] == "claude"
    payload, headers = provider.client.seen
    assert payload["output_config"]["format"]["type"] == "json_schema"
    assert headers["anthropic-version"] == "2023-06-01"
    provider.client = CapturingJsonClient({"stop_reason": "refusal", "content": []})
    with pytest.raises(ProviderResponseError, match="refusal"):
        provider.complete_json(request())


def test_gemini_provider_uses_json_schema_and_validates_model_name():
    provider = GeminiProvider(
        base_url="https://generativelanguage.googleapis.com/v1beta",
        model="gemini-test",
        api_key="key",
    )
    provider.client = CapturingJsonClient(
        {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": json.dumps(
                                    {"name": "gemini", "steps": [1]}
                                )
                            }
                        ]
                    }
                }
            ]
        }
    )
    assert provider.complete_json(request())["name"] == "gemini"
    payload, headers = provider.client.seen
    assert payload["generationConfig"]["responseJsonSchema"] == SCHEMA
    assert headers["x-goog-api-key"] == "key"
    with pytest.raises(ValueError, match="model name"):
        GeminiProvider(
            base_url="https://generativelanguage.googleapis.com/v1beta",
            model="../bad",
            api_key="key",
        )


def test_routing_provider_honours_roles_then_round_robins():
    codex = MockProvider(
        [
            {"name": "codex", "steps": [1]},
            {"name": "codex", "steps": [1]},
        ]
    )
    claude = MockProvider(
        [
            {"name": "claude", "steps": [1]},
            {"name": "again", "steps": [1]},
        ]
    )
    routed = RoutingProvider(
        [
            ProviderRoute("codex", codex, frozenset({"recon"})),
            ProviderRoute("claude", claude, frozenset({"critic"})),
        ]
    )
    recon = request(metadata={"role": "recon"})
    assert routed.complete_json(recon)["name"] == "codex"
    assert routed.last_route == "codex"
    critic = request(metadata={"role": "critic"})
    assert routed.complete_json(critic)["name"] == "claude"
    assert routed.last_route == "claude"
    # With no explicit route, the global counter continues deterministically.
    assert routed.complete_json(request(metadata={"role": "arena-operator"}))["name"] == "codex"
