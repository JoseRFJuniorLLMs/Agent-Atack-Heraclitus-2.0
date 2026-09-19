"""Contracts and strict JSON validation for model providers.

Providers are deliberately *not* tool runtimes.  They receive bounded text and
return one JSON object; they never receive a shell, a filesystem handle or a
network client that the model can direct.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, Callable, Mapping, Protocol, runtime_checkable


class ProviderError(RuntimeError):
    """Base class for model-provider failures."""


class ProviderResponseError(ProviderError):
    """The provider returned malformed, oversized or schema-invalid output."""


@dataclass(frozen=True, slots=True)
class CompletionRequest:
    """One bounded JSON-only completion.

    ``fallback_json`` is consumed only by deterministic/offline providers.  It
    is never sent to a remote model endpoint.
    """

    system_prompt: str
    user_prompt: str
    json_schema: Mapping[str, Any]
    schema_name: str = "attack_plan"
    temperature: float = 0.0
    max_output_chars: int = 32_768
    fallback_json: Mapping[str, Any] | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.system_prompt.strip() or not self.user_prompt.strip():
            raise ValueError("system_prompt and user_prompt must be non-empty")
        if not (0.0 <= self.temperature <= 2.0):
            raise ValueError("temperature must be between 0 and 2")
        if not (256 <= self.max_output_chars <= 262_144):
            raise ValueError("max_output_chars outside the safe range")


@runtime_checkable
class LLMProvider(Protocol):
    """Minimal provider boundary used by all planning agents."""

    def complete_json(self, request: CompletionRequest) -> Mapping[str, Any]:
        """Return one object validated against ``request.json_schema``."""


def parse_strict_json_object(raw: str, *, max_chars: int) -> dict[str, Any]:
    """Parse exactly one JSON object, rejecting prose and markdown fences."""

    if len(raw) > max_chars:
        raise ProviderResponseError(
            f"model output exceeds {max_chars} characters"
        )
    try:
        decoded = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ProviderResponseError("model output is not strict JSON") from exc
    if not isinstance(decoded, dict):
        raise ProviderResponseError("model output must be one JSON object")
    return decoded


def validate_json_schema(
    value: Any,
    schema: Mapping[str, Any],
    *,
    path: str = "$",
) -> None:
    """Validate the intentionally small JSON-Schema subset used by the lab.

    Supporting the subset locally keeps the project dependency-free while the
    server-side provider is still asked to enforce the same strict schema.
    Unknown schema keywords are ignored, but all structural and size controls
    used by :func:`attack_plan_json_schema` are enforced here.
    """

    expected = schema.get("type")
    if isinstance(expected, list):
        errors: list[str] = []
        for candidate in expected:
            try:
                validate_json_schema(value, {**schema, "type": candidate}, path=path)
                return
            except ProviderResponseError as exc:
                errors.append(str(exc))
        raise ProviderResponseError(f"{path}: no allowed type matched")

    type_checks: dict[str, Callable[[Any], bool]] = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "null": lambda item: item is None,
    }
    if expected in type_checks and not type_checks[str(expected)](value):
        raise ProviderResponseError(f"{path}: expected {expected}")

    if "enum" in schema and value not in schema["enum"]:
        raise ProviderResponseError(f"{path}: value is not in the allowed enum")

    if isinstance(value, str):
        minimum = int(schema.get("minLength", 0))
        maximum = int(schema.get("maxLength", 2**31 - 1))
        if not (minimum <= len(value) <= maximum):
            raise ProviderResponseError(f"{path}: string length outside bounds")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ProviderResponseError(f"{path}: number is below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise ProviderResponseError(f"{path}: number exceeds maximum")

    if isinstance(value, list):
        minimum = int(schema.get("minItems", 0))
        maximum = int(schema.get("maxItems", 2**31 - 1))
        if not (minimum <= len(value) <= maximum):
            raise ProviderResponseError(f"{path}: array length outside bounds")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                validate_json_schema(item, item_schema, path=f"{path}[{index}]")

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                raise ProviderResponseError(f"{path}: missing required field {key!r}")
        if schema.get("additionalProperties") is False:
            unknown = set(value) - set(properties)
            if unknown:
                name = sorted(unknown)[0]
                raise ProviderResponseError(f"{path}: unexpected field {name!r}")
        if isinstance(properties, Mapping):
            for key, item in value.items():
                child_schema = properties.get(key)
                if isinstance(child_schema, Mapping):
                    validate_json_schema(item, child_schema, path=f"{path}.{key}")


def validated_object(
    value: Mapping[str, Any], schema: Mapping[str, Any]
) -> dict[str, Any]:
    """Copy and validate a provider object so callers cannot mutate it later."""

    try:
        copied = json.loads(json.dumps(value, ensure_ascii=False))
    except (TypeError, ValueError) as exc:
        raise ProviderResponseError("provider result is not JSON serializable") from exc
    validate_json_schema(copied, schema)
    return copied
