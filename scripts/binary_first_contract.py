#!/usr/bin/env python3
"""Versioned contracts for the binary-first analysis engine.

This module deliberately contains no graph-building or change-detection logic.
It freezes identities and truth-table boundaries for the single authoritative
binary-first pipeline.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from functools import lru_cache
from json.encoder import encode_basestring


PHASE_ORDER = (
    "step4a_artifact_local_diff",
    "step5a_target_independent_reconciliation",
    "step4b_decision_projection_freeze",
    "step5b_trace",
    "step6_report",
)

FORMAL_REACHABILITY_STATUSES = (
    "reachable",
    "uncertain",
    "not_found_in_static_analysis",
    "not_analyzed",
)
FORMAL_IMPACT_CONCLUSIONS = ("probable_impact", "inconclusive")
FORMAL_RUNTIME_VERIFICATION_STATUSES = (
    "required_not_executed",
    "undetermined",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_JSON_ENCODER = json.JSONEncoder(
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
)
_STREAMING_DIGEST_BUFFER_CHARS = 64 * 1024
JVM_TEXT_TRANSPORT_PREFIX = "~jua-utf16-v1~"


class BinaryFirstContractError(ValueError):
    """Raised when a binary-first identity or state contract is violated."""

    def __init__(self, reason_code, message):
        super().__init__(message)
        self.reason_code = str(reason_code or "BINARY_FIRST_CONTRACT_VIOLATION")


def _escape_json_surrogates(value: str) -> str:
    """Escape surrogate code units in text already encoded as JSON.

    ``json.dumps(..., ensure_ascii=False)`` correctly quotes backslashes and
    control characters but deliberately leaves UTF-16 surrogate code units in
    the returned Python string.  Escaping only those remaining code units
    makes the JSON UTF-8 encodable without changing the frozen bytes for any
    ordinary Unicode payload.  A literal ``\\ud800`` remains distinct because
    its backslash was already JSON-escaped.
    """

    if not any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        return value
    return "".join(
        f"\\u{ord(character):04x}"
        if 0xD800 <= ord(character) <= 0xDFFF
        else character
        for character in value
    )


def _surrogate_safe_text(value: str) -> str:
    """Return UTF-8-safe text without scanning ordinary JSON in Python.

    UTF-8 encoding is implemented in C and is substantially cheaper than a
    Python character walk for the overwhelmingly common surrogate-free case.
    Only the exceptional JVM string containing a surrogate pays for the
    lossless escaping pass.
    """

    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return _escape_json_surrogates(value)
    return value


def _surrogate_safe_utf8(value: str) -> bytes:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        return _escape_json_surrogates(value).encode("utf-8")


def surrogate_safe_json_dumps(value, **kwargs) -> str:
    """Return lossless JSON text that is always strict-UTF-8 encodable."""

    return _surrogate_safe_text(json.dumps(value, **kwargs))


def surrogate_safe_json_bytes(value, **kwargs) -> bytes:
    return _surrogate_safe_utf8(json.dumps(value, **kwargs))


def _encode_basestring_surrogate_safe(value: str) -> str:
    return _surrogate_safe_text(encode_basestring(value))


def canonical_json_string(value: str) -> str:
    """Encode one string with the frozen compact canonical-JSON spelling.

    Hot identity builders that already own a canonical JSON subtree can use
    this scalar primitive to assemble the enclosing object without decoding
    and re-encoding that subtree.  Keeping the surrogate-safe implementation
    here prevents those optimized builders from drifting from the general
    canonical identity contract.
    """

    if type(value) is not str:
        raise BinaryFirstContractError(
            "BINARY_IDENTITY_STRING_INVALID",
            "canonical JSON string values must be native strings",
        )
    return _encode_basestring_surrogate_safe(value)


def _jvm_text_requires_transport(value: str) -> bool:
    if value.startswith(JVM_TEXT_TRANSPORT_PREFIX):
        return True
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return False


def transport_jvm_text(value: str) -> str:
    """Encode one raw JVM UTF-16 string for safe internal text storage.

    The reserved prefix is escaped as well, making the mapping injective: a
    genuine lone surrogate can never collide with a legal JVM string that
    merely looks like its transport representation.
    """

    if not _jvm_text_requires_transport(value):
        return value
    encoded = base64.urlsafe_b64encode(
        value.encode("utf-16-be", errors="surrogatepass")
    ).decode("ascii")
    return JVM_TEXT_TRANSPORT_PREFIX + encoded


def restore_jvm_text(value: str) -> str:
    """Reverse :func:`transport_jvm_text` for JVM protocol boundaries."""

    if not value.startswith(JVM_TEXT_TRANSPORT_PREFIX):
        return value
    payload = value[len(JVM_TEXT_TRANSPORT_PREFIX):]
    try:
        raw = base64.b64decode(
            payload.encode("ascii"), altchars=b"-_", validate=True
        )
        if len(raw) % 2:
            raise ValueError("UTF-16 transport byte length must be even")
        return raw.decode("utf-16-be", errors="surrogatepass")
    except (UnicodeEncodeError, ValueError) as error:
        raise BinaryFirstContractError(
            "BINARY_JVM_TEXT_TRANSPORT_INVALID",
            "invalid JVM UTF-16 transport value",
        ) from error


def _jvm_value_requires_transport(value) -> bool:
    value_type = type(value)
    if value_type is str:
        return _jvm_text_requires_transport(value)
    if value_type is dict:
        return any(
            (type(key) is str and _jvm_text_requires_transport(key))
            or _jvm_value_requires_transport(item)
            for key, item in value.items()
        )
    if value_type in (list, tuple):
        return any(_jvm_value_requires_transport(item) for item in value)
    return False


def transport_jvm_value(value):
    """Copy a raw JSON tree only when JVM text needs transport encoding."""

    if not _jvm_value_requires_transport(value):
        return value

    def convert(item):
        item_type = type(item)
        if item_type is str:
            return transport_jvm_text(item)
        if item_type is dict:
            return {
                (
                    transport_jvm_text(key)
                    if type(key) is str else key
                ): convert(child)
                for key, child in item.items()
            }
        if item_type is list:
            return [convert(child) for child in item]
        if item_type is tuple:
            return tuple(convert(child) for child in item)
        return item

    return convert(value)


class StreamingCanonicalSequence:
    """Repeatable lazy array accepted only by the streaming identity encoder.

    The ordinary identity API intentionally continues to reject arbitrary
    iterables: accepting a one-shot generator there would make identities
    depend on call order.  Large, already ordered evidence sets can opt into
    this wrapper with a factory that returns a fresh iterator for every pass.
    """

    __slots__ = ("_iterator_factory",)

    def __init__(self, iterator_factory):
        if not callable(iterator_factory):
            raise BinaryFirstContractError(
                "BINARY_STREAMING_SEQUENCE_FACTORY_INVALID",
                "streaming sequence requires a callable iterator factory",
            )
        self._iterator_factory = iterator_factory

    def __iter__(self):
        return iter(self._iterator_factory())


def _canonical_value(value):
    value_type = type(value)
    # Identities overwhelmingly consist of ordinary JSON trees. Test their
    # exact built-in types before the abstract ``Mapping`` checks below;
    # asking the ABC machinery about every string, integer and boolean in a
    # large fact graph is pure overhead. Subclasses and extension containers
    # still fall through to the historical generic branches unchanged.
    if value is None or value_type in (str, int, float, bool):
        return value
    if value_type is dict:
        if any(not isinstance(key, str) for key in value):
            raise BinaryFirstContractError(
                "BINARY_IDENTITY_KEY_INVALID",
                "identity object keys must be strings",
            )
        # The JSON encoder below already sorts object keys. Preserve ordinary
        # dict/list/tuple containers when every child is natively encodable so
        # the hot identity path validates once without copying the full tree.
        for item in value.values():
            if _canonical_value(item) is not item:
                break
        else:
            return value
        return {key: _canonical_value(item) for key, item in value.items()}
    if value_type in (list, tuple):
        for item in value:
            if _canonical_value(item) is not item:
                break
        else:
            return value
        return [_canonical_value(item) for item in value]
    if value_type is set:
        canonical_items = [_canonical_value(item) for item in value]
        return sorted(
            canonical_items,
            key=lambda item: surrogate_safe_json_dumps(
                item, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
        )
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise BinaryFirstContractError(
                "BINARY_IDENTITY_KEY_INVALID",
                "identity object keys must be strings",
            )
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        for item in value:
            if _canonical_value(item) is not item:
                break
        else:
            return value
        return [_canonical_value(item) for item in value]
    if isinstance(value, set):
        canonical_items = [_canonical_value(item) for item in value]
        return sorted(
            canonical_items,
            key=lambda item: surrogate_safe_json_dumps(
                item, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
        )
    if isinstance(value, (str, int, float, bool)):
        return value
    raise BinaryFirstContractError(
        "BINARY_IDENTITY_VALUE_UNSUPPORTED",
        f"unsupported identity value type: {type(value).__name__}",
    )


def canonical_payload_bytes(payload):
    canonical = _canonical_value(payload)
    return surrogate_safe_json_bytes(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_identity(namespace, payload, *, schema_version):
    namespace = str(namespace or "").strip()
    schema_version = str(schema_version or "").strip()
    if not namespace or not schema_version:
        raise BinaryFirstContractError(
            "BINARY_IDENTITY_NAMESPACE_MISSING",
            "identity namespace and schema_version are required",
        )
    envelope = {
        "namespace": namespace,
        "schema_version": schema_version,
        # ``canonical_payload_bytes`` canonicalizes the complete envelope.
        # Canonicalizing the nested payload here as well walked every member,
        # edge and reconciliation identity tree twice without changing one
        # output byte.
        "payload": payload,
    }
    return hashlib.sha256(canonical_payload_bytes(envelope)).hexdigest()


def canonical_identity_native_json(namespace, payload, *, schema_version):
    """Hash an internally constructed native JSON tree without a second walk.

    This is deliberately separate from :func:`canonical_identity`. Public and
    boundary-facing callers must keep the general API, which canonicalizes
    sets, Mapping subclasses and container subclasses and rejects non-string
    keys with the frozen reason code. Hot fact builders construct exact
    dict/list/tuple/scalar trees themselves; JSONEncoder already emits their
    frozen bytes and rejects unsupported values/NaN, so recursively walking
    every scalar first adds no correctness evidence.
    """
    namespace = str(namespace or "").strip()
    schema_version = str(schema_version or "").strip()
    if not namespace or not schema_version:
        raise BinaryFirstContractError(
            "BINARY_IDENTITY_NAMESPACE_MISSING",
            "identity namespace and schema_version are required",
        )
    prefix, suffix = _native_identity_envelope_bytes(namespace, schema_version)
    digest = hashlib.sha256(prefix)
    digest.update(_surrogate_safe_utf8(_CANONICAL_JSON_ENCODER.encode(payload)))
    digest.update(suffix)
    return digest.hexdigest()


@lru_cache(maxsize=256)
def _native_identity_envelope_bytes(
    namespace: str, schema_version: str
) -> tuple[bytes, bytes]:
    # Object keys are sorted as namespace, payload, schema_version.
    return (
        (
            '{"namespace":' + _encode_basestring_surrogate_safe(namespace)
            + ',"payload":'
        ).encode("utf-8"),
        (
            ',"schema_version":'
            + _encode_basestring_surrogate_safe(schema_version) + "}"
        ).encode("utf-8"),
    )


def _iter_canonical_json(value):
    """Yield the existing canonical JSON encoding without copying its tree."""
    value_type = type(value)
    if value is None:
        yield "null"
        return
    if value_type is str:
        yield _encode_basestring_surrogate_safe(value)
        return
    if value_type is bool:
        yield "true" if value else "false"
        return
    if value_type is int:
        yield str(value)
        return
    if value_type is float:
        # Preserve allow_nan=False and JSONEncoder's exact float spelling.
        yield _CANONICAL_JSON_ENCODER.encode(value)
        return
    if value_type is dict:
        if any(not isinstance(key, str) for key in value):
            raise BinaryFirstContractError(
                "BINARY_IDENTITY_KEY_INVALID",
                "identity object keys must be strings",
            )
        yield "{"
        for index, key in enumerate(sorted(value)):
            if index:
                yield ","
            yield _encode_basestring_surrogate_safe(key)
            yield ":"
            yield from _iter_canonical_json(value[key])
        yield "}"
        return
    if value_type in (list, tuple) or value_type is StreamingCanonicalSequence:
        yield "["
        for index, item in enumerate(value):
            if index:
                yield ","
            yield from _iter_canonical_json(item)
        yield "]"
        return
    if value_type is set:
        # Sets have no wire representation of their own. Match
        # ``_canonical_value`` by sorting each already-canonical item by its
        # compact JSON text and emitting the collection as an array.
        items = ["".join(_iter_canonical_json(item)) for item in value]
        yield "["
        yield ",".join(sorted(items))
        yield "]"
        return
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise BinaryFirstContractError(
                "BINARY_IDENTITY_KEY_INVALID",
                "identity object keys must be strings",
            )
        yield "{"
        for index, key in enumerate(sorted(value)):
            if index:
                yield ","
            yield _encode_basestring_surrogate_safe(key)
            yield ":"
            yield from _iter_canonical_json(value[key])
        yield "}"
        return
    if isinstance(value, (list, tuple, StreamingCanonicalSequence)):
        yield "["
        for index, item in enumerate(value):
            if index:
                yield ","
            yield from _iter_canonical_json(item)
        yield "]"
        return
    if isinstance(value, set):
        items = ["".join(_iter_canonical_json(item)) for item in value]
        yield "["
        yield ",".join(sorted(items))
        yield "]"
        return
    if isinstance(value, (str, int, float, bool)):
        yield _surrogate_safe_text(_CANONICAL_JSON_ENCODER.encode(value))
        return
    raise BinaryFirstContractError(
        "BINARY_IDENTITY_VALUE_UNSUPPORTED",
        f"unsupported identity value type: {type(value).__name__}",
    )


def canonical_identity_streaming(namespace, payload, *, schema_version):
    """Hash canonical identity bytes with memory bounded by nesting depth."""
    namespace = str(namespace or "").strip()
    schema_version = str(schema_version or "").strip()
    if not namespace or not schema_version:
        raise BinaryFirstContractError(
            "BINARY_IDENTITY_NAMESPACE_MISSING",
            "identity namespace and schema_version are required",
        )
    digest = hashlib.sha256()
    _update_canonical_digest(digest, {
        "namespace": namespace,
        "schema_version": schema_version,
        "payload": payload,
    })
    return digest.hexdigest()


def _update_canonical_digest(digest, value):
    """Write canonical JSON directly into a digest in bounded text blocks.

    ``yield from`` is elegant but makes every scalar traverse each generator
    frame above it. Runtime truth sets contain millions of shallow scalars, so
    a direct recursive writer preserves the same bytes while avoiding that
    multiplicative interpreter overhead.
    """
    buffered: list[str] = []
    buffered_chars = 0

    def append(chunk: str) -> None:
        nonlocal buffered_chars
        buffered.append(chunk)
        buffered_chars += len(chunk)
        if buffered_chars >= _STREAMING_DIGEST_BUFFER_CHARS:
            digest.update("".join(buffered).encode("utf-8"))
            buffered.clear()
            buffered_chars = 0

    def write(item) -> None:
        item_type = type(item)
        if item is None:
            append("null")
            return
        if item_type is str:
            append(_encode_basestring_surrogate_safe(item))
            return
        if item_type is bool:
            append("true" if item else "false")
            return
        if item_type is int:
            append(str(item))
            return
        if item_type is float:
            append(_CANONICAL_JSON_ENCODER.encode(item))
            return
        if item_type is dict:
            if any(not isinstance(key, str) for key in item):
                raise BinaryFirstContractError(
                    "BINARY_IDENTITY_KEY_INVALID",
                    "identity object keys must be strings",
                )
            append("{")
            for index, key in enumerate(sorted(item)):
                if index:
                    append(",")
                append(_encode_basestring_surrogate_safe(key))
                append(":")
                write(item[key])
            append("}")
            return
        if item_type in (list, tuple) or item_type is StreamingCanonicalSequence:
            append("[")
            for index, child in enumerate(item):
                if index:
                    append(",")
                write(child)
            append("]")
            return
        if item_type is set:
            texts = ["".join(_iter_canonical_json(child)) for child in item]
            append("[")
            append(",".join(sorted(texts)))
            append("]")
            return
        if isinstance(item, Mapping):
            if any(not isinstance(key, str) for key in item):
                raise BinaryFirstContractError(
                    "BINARY_IDENTITY_KEY_INVALID",
                    "identity object keys must be strings",
                )
            append("{")
            for index, key in enumerate(sorted(item)):
                if index:
                    append(",")
                append(_encode_basestring_surrogate_safe(key))
                append(":")
                write(item[key])
            append("}")
            return
        if isinstance(item, (list, tuple, StreamingCanonicalSequence)):
            append("[")
            for index, child in enumerate(item):
                if index:
                    append(",")
                write(child)
            append("]")
            return
        if isinstance(item, set):
            texts = ["".join(_iter_canonical_json(child)) for child in item]
            append("[")
            append(",".join(sorted(texts)))
            append("]")
            return
        if isinstance(item, (str, int, float, bool)):
            append(_surrogate_safe_text(_CANONICAL_JSON_ENCODER.encode(item)))
            return
        raise BinaryFirstContractError(
            "BINARY_IDENTITY_VALUE_UNSUPPORTED",
            f"unsupported identity value type: {type(item).__name__}",
        )

    write(value)
    if buffered:
        digest.update("".join(buffered).encode("utf-8"))


def artifact_content_identity(content_sha256, byte_length, *, schema_version="1"):
    content_sha256 = str(content_sha256 or "").strip().lower()
    if type(byte_length) is not int:
        raise BinaryFirstContractError(
            "ARTIFACT_CONTENT_LENGTH_INVALID", "byte_length must be a non-negative integer"
        )
    if not _SHA256_RE.fullmatch(content_sha256):
        raise BinaryFirstContractError(
            "ARTIFACT_CONTENT_SHA256_INVALID", "content_sha256 must be 64 lowercase hex characters"
        )
    if byte_length < 0:
        raise BinaryFirstContractError(
            "ARTIFACT_CONTENT_LENGTH_INVALID", "byte_length must be a non-negative integer"
        )
    payload = {
        "content_sha256": content_sha256,
        "byte_length": byte_length,
    }
    return canonical_identity(
        "artifact_content_identity", payload, schema_version=schema_version
    )


def analysis_context_identity(
    runtime_comparison_identity,
    analysis_scope_identity,
    *,
    schema_version="1",
):
    runtime_comparison_identity = str(runtime_comparison_identity or "").strip()
    analysis_scope_identity = str(analysis_scope_identity or "").strip()
    if not runtime_comparison_identity or not analysis_scope_identity:
        raise BinaryFirstContractError(
            "ANALYSIS_CONTEXT_INPUT_MISSING",
            "runtime comparison and analysis scope identities are required",
        )
    return canonical_identity(
        "analysis_context_identity",
        {
            "runtime_comparison_identity": runtime_comparison_identity,
            "analysis_scope_identity": analysis_scope_identity,
        },
        schema_version=schema_version,
    )


def observed_delta_identity(
    *,
    delta_source_kind,
    comparison_or_runtime_scope,
    fact_or_mechanism_scope,
    base_fingerprint,
    current_fingerprint,
    schema_version="1",
):
    """Build a scope-independent observed identity.

    AnalysisScopeIdentity is intentionally not accepted here. Different
    analysis scopes share the same observation and receive distinct disposition
    obligations instead.
    """
    payload = {
        "delta_source_kind": str(delta_source_kind or "").strip(),
        "comparison_or_runtime_scope": _canonical_value(
            comparison_or_runtime_scope
        ),
        "fact_or_mechanism_scope": _canonical_value(fact_or_mechanism_scope),
        "base_fingerprint": str(base_fingerprint or "").strip(),
        "current_fingerprint": str(current_fingerprint or "").strip(),
    }
    if not all(
        payload[key]
        for key in (
            "delta_source_kind",
            "comparison_or_runtime_scope",
            "fact_or_mechanism_scope",
            "base_fingerprint",
            "current_fingerprint",
        )
    ):
        raise BinaryFirstContractError(
            "OBSERVED_DELTA_INPUT_MISSING", "all observed-delta identity fields are required"
        )
    return canonical_identity(
        "observed_delta_identity", payload, schema_version=schema_version
    )


def disposition_obligation_identity(
    observed_delta_id,
    analysis_context_id,
    *,
    schema_version="1",
):
    observed_delta_id = str(observed_delta_id or "").strip()
    analysis_context_id = str(analysis_context_id or "").strip()
    if not observed_delta_id or not analysis_context_id:
        raise BinaryFirstContractError(
            "DISPOSITION_OBLIGATION_INPUT_MISSING",
            "observed delta and analysis context identities are required",
        )
    return canonical_identity(
        "disposition_obligation_identity",
        {
            "observed_delta_identity": observed_delta_id,
            "analysis_context_identity": analysis_context_id,
        },
        schema_version=schema_version,
    )


def projection_obligation_key(
    projection_rule_contract_identity,
    analysis_target_identity,
    required_edge_family,
    *,
    schema_version="1",
):
    payload = {
        "projection_rule_contract_identity": str(
            projection_rule_contract_identity or ""
        ).strip(),
        "analysis_target_identity": str(analysis_target_identity or "").strip(),
        "required_edge_family": str(required_edge_family or "").strip(),
    }
    if not all(payload.values()):
        raise BinaryFirstContractError(
            "PROJECTION_OBLIGATION_INPUT_MISSING",
            "projection rule, target, and required edge family are required",
        )
    return canonical_identity(
        "projection_obligation_key", payload, schema_version=schema_version
    )


def derive_formal_result_state(
    reachability_status,
    *,
    best_path_certainty=None,
    possible_path_exists=None,
):
    reachability_status = str(reachability_status or "").strip()
    if reachability_status not in FORMAL_REACHABILITY_STATUSES:
        raise BinaryFirstContractError(
            "FORMAL_REACHABILITY_STATUS_INVALID",
            f"unsupported formal reachability status: {reachability_status or '<empty>'}",
        )
    expected_certainty = {
        "reachable": "exact_or_proven",
        "uncertain": "possible",
        "not_found_in_static_analysis": "none",
        "not_analyzed": "none",
    }[reachability_status]
    certainty = str(best_path_certainty or expected_certainty).strip()
    if certainty != expected_certainty:
        raise BinaryFirstContractError(
            "FORMAL_BEST_PATH_CERTAINTY_INVALID",
            f"{reachability_status} requires best_path_certainty={expected_certainty}",
        )
    reachable = reachability_status == "reachable"
    if reachability_status == "reachable":
        possible_exists = bool(possible_path_exists)
    elif reachability_status == "uncertain":
        if possible_path_exists is False:
            raise BinaryFirstContractError(
                "FORMAL_POSSIBLE_PATH_STATE_INVALID",
                "uncertain requires at least one complete possible path",
            )
        possible_exists = True
    else:
        if possible_path_exists:
            raise BinaryFirstContractError(
                "FORMAL_POSSIBLE_PATH_STATE_INVALID",
                f"{reachability_status} cannot claim a complete possible path",
            )
        possible_exists = False
    return {
        "change_fact_status": "confirmed",
        "reachability_status": reachability_status,
        "analysis_status": reachability_status,
        "is_reachable": reachable,
        "impact_conclusion": "probable_impact" if reachable else "inconclusive",
        "decision_bucket": "probable_impact" if reachable else "inconclusive",
        "runtime_verification_status": (
            "required_not_executed" if reachable else "undetermined"
        ),
        "runtime_verification_executed_by_system": False,
        "runtime_verification_evidence": [],
        "best_path_certainty": certainty,
        "existence_proven": reachable,
        "exact_path_exists": reachable,
        # A reachable target can also have additional possible paths. Those
        # paths lower path-set completeness, never the already-proven
        # reachability result.
        "possible_path_exists": possible_exists,
    }


def validate_formal_result_state(payload):
    payload = dict(payload or {})
    if payload.get("change_fact_status") != "confirmed":
        raise BinaryFirstContractError(
            "FORMAL_CHANGE_FACT_NOT_CONFIRMED",
            "formal results require change_fact_status=confirmed",
        )
    derived = derive_formal_result_state(
        payload.get("reachability_status"),
        best_path_certainty=payload.get("best_path_certainty"),
        possible_path_exists=payload.get("possible_path_exists"),
    )
    forbidden = {
        "confirmed_impact",
        "confirmed_no_impact",
        "not_required",
        "passed",
        "failed",
    }
    observed_values = {
        str(payload.get("impact_conclusion") or "").strip(),
        str(payload.get("decision_bucket") or "").strip(),
        str(payload.get("runtime_verification_status") or "").strip(),
    }
    if forbidden & observed_values:
        raise BinaryFirstContractError(
            "FORMAL_STATIC_V2_FORBIDDEN_STATE",
            "static v2 cannot emit confirmed impact/no-impact, not_required, passed, or failed",
        )
    for key in (
        "analysis_status",
        "is_reachable",
        "impact_conclusion",
        "decision_bucket",
        "runtime_verification_status",
        "runtime_verification_executed_by_system",
        "runtime_verification_evidence",
        "existence_proven",
        "exact_path_exists",
        "possible_path_exists",
    ):
        if payload.get(key) != derived[key]:
            raise BinaryFirstContractError(
                "FORMAL_STATE_TRUTH_TABLE_VIOLATION",
                f"{key}={payload.get(key)!r} conflicts with {payload.get('reachability_status')}",
            )
    return derived


def derive_path_set_complete(
    *,
    exact_path_set_complete,
    possible_path_layer_applicable,
    possible_path_set_complete,
):
    return bool(exact_path_set_complete) and (
        not bool(possible_path_layer_applicable)
        or bool(possible_path_set_complete)
    )


def validate_projection_assessment(payload):
    payload = dict(payload or {})
    status = str(payload.get("analysis_projection_status") or "").strip()
    coverage = str(payload.get("projection_coverage_status") or "").strip()
    target_count = int(payload.get("target_count") or 0)
    obligation_count = int(payload.get("projection_obligation_count") or 0)
    projection_count = int(payload.get("projection_count") or 0)
    partial_scopes = list(payload.get("partial_scopes") or [])
    if status == "unsupported":
        if coverage != "unsupported" or any(
            (target_count, obligation_count, projection_count, len(partial_scopes))
        ):
            raise BinaryFirstContractError(
                "UNSUPPORTED_PROJECTION_ASSESSMENT_INVALID",
                "unsupported assessments require zero targets/obligations/projections/partial scopes",
            )
    elif status == "targetable":
        if coverage not in {"complete", "partial"}:
            raise BinaryFirstContractError(
                "TARGETABLE_PROJECTION_COVERAGE_INVALID",
                "targetable assessment coverage must be complete or partial",
            )
        if target_count <= 0 or obligation_count <= 0:
            raise BinaryFirstContractError(
                "TARGETABLE_PROJECTION_OBLIGATION_MISSING",
                "targetable assessments require at least one target and obligation",
            )
        if obligation_count != projection_count:
            raise BinaryFirstContractError(
                "PROJECTION_OBLIGATION_COUNT_MISMATCH",
                "every projection obligation requires exactly one projection",
            )
        if coverage == "complete" and partial_scopes:
            raise BinaryFirstContractError(
                "COMPLETE_PROJECTION_HAS_PARTIAL_SCOPE",
                "complete targetable assessments cannot reference partial scopes",
            )
        if coverage == "partial" and not partial_scopes:
            raise BinaryFirstContractError(
                "PARTIAL_PROJECTION_SCOPE_MISSING",
                "partial targetable assessments require at least one partial scope",
            )
    else:
        raise BinaryFirstContractError(
            "PROJECTION_ASSESSMENT_STATUS_INVALID",
            "analysis_projection_status must be targetable or unsupported",
        )
    return True


def validate_phase_manifest(records):
    records = [dict(item or {}) for item in (records or [])]
    seen = set()
    completed_prefix = 0
    for item in records:
        phase = str(item.get("phase") or "").strip()
        if phase not in PHASE_ORDER or phase in seen:
            raise BinaryFirstContractError(
                "BINARY_PHASE_MANIFEST_INVALID", f"invalid or duplicate phase: {phase or '<empty>'}"
            )
        expected = PHASE_ORDER[len(seen)]
        if phase != expected:
            raise BinaryFirstContractError(
                "BINARY_PHASE_ORDER_INVALID", f"expected {expected} before {phase}"
            )
        seen.add(phase)
        status = str(item.get("status") or "").strip()
        if status not in {"completed", "failed", "blocked", "pending"}:
            raise BinaryFirstContractError(
                "BINARY_PHASE_STATUS_INVALID", f"invalid phase status: {status or '<empty>'}"
            )
        if status == "completed":
            if not str(item.get("input_digest") or "").strip() or not str(
                item.get("output_digest") or ""
            ).strip():
                raise BinaryFirstContractError(
                    "BINARY_PHASE_DIGEST_MISSING", "completed phases require input and output digests"
                )
            completed_prefix += 1
        elif len(seen) != len(records):
            raise BinaryFirstContractError(
                "BINARY_PHASE_AFTER_TERMINAL_STATE",
                "no later phase may follow a non-completed phase",
            )
    return {"completed_phase_count": completed_prefix, "next_phase": (
        PHASE_ORDER[completed_prefix] if completed_prefix < len(PHASE_ORDER) else ""
    )}


__all__ = [
    "BinaryFirstContractError",
    "FORMAL_IMPACT_CONCLUSIONS",
    "FORMAL_REACHABILITY_STATUSES",
    "FORMAL_RUNTIME_VERIFICATION_STATUSES",
    "JVM_TEXT_TRANSPORT_PREFIX",
    "PHASE_ORDER",
    "analysis_context_identity",
    "artifact_content_identity",
    "canonical_identity",
    "canonical_json_string",
    "canonical_payload_bytes",
    "derive_formal_result_state",
    "derive_path_set_complete",
    "disposition_obligation_identity",
    "observed_delta_identity",
    "projection_obligation_key",
    "validate_formal_result_state",
    "validate_phase_manifest",
    "validate_projection_assessment",
]
