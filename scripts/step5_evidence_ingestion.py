#!/usr/bin/env python3
"""Single validated ingestion boundary for post-source Step5 evidence."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import io
import json
from pathlib import Path
import re
import struct
from types import SimpleNamespace
from typing import Iterable, Mapping, Tuple
import zipfile
from xml.etree import ElementTree as ET

from enhanced_source_analyzer import CallEdge
from signature_utils import normalize_signature_for_lookup
from step5_evidence_model import (
    CollectedEdge,
    CollectorBatch,
    EvidenceFailure,
    EvidenceFailureOccurrence,
    ModuleScope,
    thaw_evidence_value,
)


@dataclass(frozen=True)
class IngestionResult:
    merged_edges: int
    duplicate_edges: int
    rejected_edges: int
    failures: Tuple[EvidenceFailure, ...]
    merged_by_collector: Tuple[Tuple[str, int], ...] = ()
    duplicate_by_collector: Tuple[Tuple[str, int], ...] = ()
    rejected_by_collector: Tuple[Tuple[str, int], ...] = ()
    failures_by_collector: Tuple[Tuple[str, EvidenceFailure], ...] = ()
    matched_callback_edges: int = 0
    unmatched_callback_edges: int = 0
    framework_entry_methods: int = 0
    runtime_framework_entry_methods: int = 0
    framework_activation_linked_methods: int = 0
    framework_proxy_dispatch_edges: int = 0
    framework_mybatis_proxy_dispatch_edges: int = 0
    framework_transaction_proxy_edges: int = 0
    framework_activation_edges: int = 0
    ambiguous_framework_proxy_dispatches: int = 0

    def framework_projection_stats(self):
        return {
            "matched_callback_edges": self.matched_callback_edges,
            "unmatched_callback_edges": self.unmatched_callback_edges,
            "framework_entry_methods": self.framework_entry_methods,
            "runtime_framework_entry_methods": self.runtime_framework_entry_methods,
            "framework_activation_linked_methods": self.framework_activation_linked_methods,
            "framework_proxy_dispatch_edges": self.framework_proxy_dispatch_edges,
            "framework_mybatis_proxy_dispatch_edges": (
                self.framework_mybatis_proxy_dispatch_edges
            ),
            "framework_transaction_proxy_edges": (
                self.framework_transaction_proxy_edges
            ),
            "framework_activation_edges": self.framework_activation_edges,
            "ambiguous_framework_proxy_dispatches": (
                self.ambiguous_framework_proxy_dispatches
            ),
        }


def _edge_identity(edge: CollectedEdge):
    return (
        edge.caller_symbol,
        edge.callee_symbol,
        edge.edge_kind,
        edge.semantic,
        edge.provenance.artifact_sha256,
        edge.provenance.artifact_entry,
        edge.provenance.line,
        edge.provenance.instruction_offset,
    )


def _callee_simple_key(symbol: str) -> str:
    prefix = str(symbol or "").split("(", 1)[0]
    member = prefix.rsplit(".", 1)[-1]
    if "(" in str(symbol or ""):
        parameters = str(symbol).split("(", 1)[1]
        return f"method:{member}({parameters}"
    return f"field:{member}"


def _owner_type(scope: ModuleScope) -> str:
    if scope == ModuleScope.BUSINESS_CLASSES:
        return "business"
    if scope in {ModuleScope.INTERNAL_MODULE, ModuleScope.EXTERNAL_DEPENDENCY}:
        return "dependency"
    return "unknown"


def _edge_metadata(edge: CollectedEdge):
    return thaw_evidence_value(dict(edge.metadata))


def _call_edge_identity(edge, collector):
    identity = (
        str(getattr(edge, "caller_symbol_id", "") or ""),
        str(getattr(edge, "callee_key", "") or ""),
        str(getattr(edge, "evidence_type", "") or ""),
    )
    artifact_sha = str(getattr(edge, "artifact_sha256", "") or "")
    artifact_entry = str(getattr(edge, "artifact_entry", "") or "")
    raw_instruction_offset = getattr(edge, "instruction_offset", -1)
    instruction_offset = (
        -1 if raw_instruction_offset is None else int(raw_instruction_offset)
    )
    if artifact_sha or artifact_entry or instruction_offset >= 0 or collector == "indirect_usage":
        return (
            *identity,
            artifact_sha,
            artifact_entry,
            int(getattr(edge, "line", 0) or 0),
            instruction_offset,
        )
    return identity


_FRAMEWORK_COLLECTORS = {
    "java_spi",
    "spring_basic",
    "spring_runtime_artifact",
    "spring_transaction_proxy",
    "spring_data_repository_proxy",
    "mybatis",
    "mybatis_mapper_proxy",
    "dynamic_proxy_basic",
    "declarative_http_client_basic",
    "spring_aop_activation",
    "spring_security_filter_activation",
}

_FRAMEWORK_ENTRY_KINDS = {
    "spring_event_listener",
    "spring_framework_callback",
    "spring_bean_dispatch",
    "spring_runtime_active_entry",
    "java_spi_load_point",
    "java_spi_registration",
    "dubbo_spi_registration",
    "mybatis_mapper_binding",
    "mybatis_annotation_binding",
    "mybatis_type_reference",
    "mybatis_type_handler_binding",
    "mybatis_type_handler_registration",
    "mybatis_plugin_registration",
    "spring_autoconfiguration_registration",
    "spring_factories_registration",
    "spring_runtime_registered_callback",
    "spring_runtime_autoconfiguration_registration",
}


def _is_framework_batch(batch: CollectorBatch) -> bool:
    if batch.collector in _FRAMEWORK_COLLECTORS:
        return True
    return any(
        "framework_source" in _edge_metadata(edge)
        or "legacy_edge" in _edge_metadata(edge)
        for edge in batch.edges
    )


def _framework_edge_identity(batch: CollectorBatch, edge: CollectedEdge):
    metadata = json.dumps(
        dict(edge.metadata),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return (batch.collector, batch.version, *_edge_identity(edge), metadata)


def _framework_edge_mapping(
    batch: CollectorBatch,
    edge: CollectedEdge,
) -> Mapping[str, object]:
    metadata = _edge_metadata(edge)
    provenance = metadata.get("framework_provenance")
    if not isinstance(provenance, Mapping):
        provenance = {}
    result = {
        key: value
        for key, value in metadata.items()
        if key not in {
            "legacy_edge",
            "framework_source",
            "framework_target",
            "framework_provenance",
        }
    }
    result.update({
        "source": edge.caller_symbol,
        "target": edge.callee_symbol,
        "edge_kind": edge.edge_kind,
        "confidence": edge.confidence,
        "conditions": thaw_evidence_value(edge.activation_conditions),
        "ambiguity": edge.ambiguous,
        "activation_verified": edge.activation_verified,
        "activation_evidence": [
            {
                "authority": item.authority.value,
                "proof_kind": item.proof_kind,
                "source": item.source,
                "artifact_sha256": item.artifact_sha256,
                "detail": item.detail,
            }
            for item in edge.activation_evidence
        ],
        "provenance": {
            **dict(provenance),
            **({"artifact_path": edge.provenance.artifact_path}
               if edge.provenance.artifact_path else {}),
            **({"artifact_sha256": edge.provenance.artifact_sha256}
               if edge.provenance.artifact_sha256 else {}),
            **({"artifact_entry": edge.provenance.artifact_entry}
               if edge.provenance.artifact_entry else {}),
            **({"class_or_resource_entry": edge.provenance.class_or_resource_entry}
               if edge.provenance.class_or_resource_entry else {}),
            **({"parser": edge.provenance.parser}
               if edge.provenance.parser else {}),
            **({"evidence_source": edge.provenance.evidence_source}
               if edge.provenance.evidence_source else {}),
        },
        "adapter": batch.collector,
        "adapter_version": batch.version,
    })
    return result


def _method_key_parts(value):
    match = re.match(
        r"^(?P<owner>[\w.$]+)\.(?P<member>[\w$<>]+)\((?P<parameters>.*)\)$",
        str(value or "").strip(),
    )
    if not match:
        return None
    parameters = match.group("parameters").strip()
    parameter_count = 0 if not parameters else len(parameters.split(","))
    return match.group("owner"), match.group("member"), parameter_count


def _source_lookup_keys(reverse_edge_snapshot, source_identity):
    return [
        lookup_key
        for lookup_key, callers in reverse_edge_snapshot.items()
        if callers and _method_key_parts(lookup_key) == source_identity
    ]


def _framework_proxy_source_identities(records):
    identities = set()
    for _batch, edge, edge_mapping in records:
        if edge.edge_kind in {
            "mybatis_mapper_proxy_dispatch",
            "spring_transaction_proxy_dispatch",
        }:
            identity = (
                str(edge_mapping.get("source_owner") or ""),
                str(edge_mapping.get("source_member") or ""),
                int(edge_mapping.get("parameter_count") or 0),
            )
        elif edge.edge_kind == "spring_data_repository_proxy_dispatch":
            identity = (
                str(edge_mapping.get("source") or ""),
                str(edge_mapping.get("target_member") or ""),
                int(edge_mapping.get("parameter_count") or 0),
            )
        else:
            continue
        if identity[0] and identity[1]:
            identities.add(identity)
    return identities


def _snapshot_framework_reverse_edges(reverse_edges, records):
    """Freeze only pre-framework keys queried by proxy projection."""
    source_identities = _framework_proxy_source_identities(records)
    if not source_identities:
        return {}
    return {
        lookup_key: tuple(edges)
        for lookup_key, edges in (reverse_edges or {}).items()
        if edges and _method_key_parts(lookup_key) in source_identities
    }


def _caller_evidence_rank(caller):
    if str(getattr(caller, "evidence_source", "") or "") == "current_final_artifact":
        return 3
    if getattr(caller, "runtime_analyzer_hit", None):
        return 2
    if str(getattr(caller, "evidence_type", "") or "").startswith("bytecode_"):
        return 1
    return 0


def _ranked_proxy_callers(reverse_edge_snapshot, source_keys, *, final_artifact_only=False):
    callers_by_symbol = {}
    for source_key in source_keys:
        for caller in reverse_edge_snapshot.get(source_key) or ():
            if final_artifact_only and not (
                str(getattr(caller, "evidence_source", "") or "")
                == "current_final_artifact"
                or getattr(caller, "runtime_analyzer_hit", None)
            ):
                continue
            caller_symbol = str(getattr(caller, "caller_symbol_id", "") or "")
            rank = _caller_evidence_rank(caller)
            existing = callers_by_symbol.get(caller_symbol)
            if existing is None or rank > existing[0]:
                callers_by_symbol[caller_symbol] = (rank, caller)
    return [item[1] for item in callers_by_symbol.values()]


def _target_lookup_keys(target):
    keys = [target]
    if "(" not in target or not target.endswith(")"):
        return keys
    unsigned, signature_body = target.rsplit("(", 1)
    normalized = normalize_signature_for_lookup("(" + signature_body)
    compact = normalized.replace(", ", ",") if normalized else ""
    for signature in (normalized, compact):
        alias = unsigned + signature if signature else ""
        if alias and alias not in keys:
            keys.append(alias)
    return keys


def _valid_sha256(value):
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", str(value or "")))


def _business_class_entry(value):
    entry = str(value or "").strip()
    for prefix in ("BOOT-INF/classes/", "WEB-INF/classes/"):
        if entry.startswith(prefix):
            return entry[len(prefix):]
    return entry


def _caller_evidence_fields(caller):
    return {
        "caller_evidence_source": str(
            getattr(caller, "evidence_source", "") or ""
        ),
        "caller_evidence_authority": str(
            getattr(caller, "evidence_authority", "") or ""
        ),
        "caller_evidence_type": str(
            getattr(caller, "evidence_type", "") or ""
        ),
        "caller_artifact_sha256": str(
            getattr(caller, "artifact_sha256", "") or ""
        ),
        "caller_artifact_entry": str(
            getattr(caller, "artifact_entry", "") or ""
        ),
        "caller_evidence_file": str(getattr(caller, "file", "") or ""),
        "caller_evidence_line": int(getattr(caller, "line", 0) or 0),
    }


def _framework_evidence_fields(batch, edge):
    return {
        "framework_evidence_source": (
            edge.provenance.evidence_source or edge.provenance.authority.value
        ),
        "framework_evidence_authority": edge.provenance.authority.value,
        "framework_evidence_artifact_sha256": edge.provenance.artifact_sha256,
        "framework_evidence_artifact_entry": edge.provenance.artifact_entry,
        "semantic": True,
        "collector": batch.collector,
        "framework_activation_verified": edge.activation_verified,
        "activation_evidence": tuple(edge.activation_evidence),
    }


def _proxy_call_edge(
    caller,
    batch,
    edge,
    edge_mapping,
    *,
    source_key,
    target,
    evidence_type,
    content_prefix,
    confidence=None,
    final_artifact_verified=None,
    use_framework_line=False,
):
    provenance = dict(edge_mapping.get("provenance") or {})
    values = dict(vars(caller))
    caller_evidence = _caller_evidence_fields(caller)
    values.update(caller_evidence)
    values.update(_framework_evidence_fields(batch, edge))
    values.update({
        "callee_key": target,
        "callee_simple_key": target.rsplit(".", 1)[-1],
        "evidence_type": evidence_type,
        "confidence": confidence or edge.confidence,
        "file": str(provenance.get("jar") or values.get("file") or ""),
        "content": f"{content_prefix}: {source_key} -> {target}",
        "framework_registration": True,
        "framework_source": str(edge_mapping.get("source") or ""),
        "framework_target": target,
        "framework_provenance": provenance,
        "runtime_activation": str(
            edge_mapping.get("runtime_activation") or "active"
        ),
        "evidence_source": (
            edge.provenance.evidence_source or edge.provenance.authority.value
        ),
        "evidence_authority": edge.provenance.authority.value,
        "artifact_sha256": edge.provenance.artifact_sha256,
        "artifact_entry": edge.provenance.artifact_entry,
    })
    runtime_hit = getattr(caller, "runtime_analyzer_hit", None)
    if isinstance(runtime_hit, Mapping):
        runtime_hit = dict(runtime_hit)
    elif (
        caller_evidence["caller_evidence_source"] == "current_final_artifact"
        and _valid_sha256(caller_evidence["caller_artifact_sha256"])
        and caller_evidence["caller_evidence_file"]
        and caller_evidence["caller_artifact_entry"]
    ):
        owner_coord = str(getattr(caller, "owner_coord", "") or "")
        runtime_hit = {
            "coord": (
                "__business__"
                if str(getattr(caller, "owner_type", "") or "") == "business"
                or owner_coord in {"BUSINESS", "__business__"}
                else owner_coord
            ),
            "artifact_sha256": caller_evidence["caller_artifact_sha256"],
            "artifact_path": caller_evidence["caller_evidence_file"].split("!/", 1)[0],
            "artifact_entry": caller_evidence["caller_artifact_entry"],
        }
    values["runtime_analyzer_hit"] = runtime_hit
    if use_framework_line:
        values["line"] = int(provenance.get("line") or values.get("line") or 0)
    if final_artifact_verified is not None:
        values["framework_final_artifact_verified"] = bool(final_artifact_verified)
    return SimpleNamespace(**values)


def _append_call_edge(graph, lookup_keys, edge):
    identity = (
        str(getattr(edge, "caller_symbol_id", "") or ""),
        str(getattr(edge, "callee_key", "") or ""),
        str(getattr(edge, "evidence_type", "") or ""),
    )
    attached = False
    for lookup_key in dict.fromkeys(key for key in lookup_keys if key):
        bucket = graph.reverse_edges.setdefault(lookup_key, [])
        if any(
            (
                str(getattr(existing, "caller_symbol_id", "") or ""),
                str(getattr(existing, "callee_key", "") or ""),
                str(getattr(existing, "evidence_type", "") or ""),
            )
            == identity
            for existing in bucket
        ):
            continue
        bucket.append(edge)
        attached = True
    return attached


def _resolve_caller(graph, edge: CollectedEdge):
    metadata = _edge_metadata(edge)
    if not (
        metadata.get("caller_resolution_required")
        or (metadata.get("caller_owner") and metadata.get("caller_name"))
    ):
        method = (getattr(graph, "methods_by_id", {}) or {}).get(edge.caller_symbol)
        return (
            edge.caller_symbol,
            str(metadata.get("caller_qualified_key") or edge.caller_symbol),
            method,
        )
    owner = str(metadata.get("caller_owner") or "").strip()
    name = str(metadata.get("caller_name") or "").strip()
    signature = str(metadata.get("caller_signature") or "").strip()
    qualified = f"{owner}.{name}" if owner and name else edge.caller_symbol
    raw_candidates = list(
        (getattr(graph, "methods_by_qualified", {}) or {}).get(qualified) or []
    )
    candidates = []
    methods_by_id = getattr(graph, "methods_by_id", {}) or {}
    for candidate in raw_candidates:
        method = candidate if hasattr(candidate, "symbol_id") else methods_by_id.get(candidate)
        if method is not None:
            candidates.append(method)
    if len(candidates) == 1:
        candidate = candidates[0]
        return candidate.symbol_id, getattr(candidate, "qualified_key", "") or qualified, candidate
    if signature and len(candidates) > 1:
        candidates = [
            candidate for candidate in candidates
            if any(
                str(key).endswith(signature)
                for key in (getattr(graph, "lookup_keys_by_symbol", {}) or {}).get(
                    candidate.symbol_id, ()
                )
            )
        ]
    if len(candidates) != 1:
        return None, qualified, None
    candidate = candidates[0]
    return candidate.symbol_id, getattr(candidate, "qualified_key", "") or qualified, candidate


def _to_call_edge(
    edge: CollectedEdge,
    collector: str,
    *,
    caller_symbol: str,
    caller_qualified_key: str,
    caller_method=None,
) -> CallEdge:
    metadata = _edge_metadata(edge)
    evidence_path = edge.provenance.artifact_path or edge.provenance.artifact_entry
    if edge.provenance.artifact_path and edge.provenance.artifact_entry:
        evidence_path = (
            f"{edge.provenance.artifact_path}!/{edge.provenance.artifact_entry}"
        )
    owner_type = str(metadata.get("owner_type") or "")
    owner_coord = str(metadata.get("owner_coord") or "")
    module = str(metadata.get("module") or "")
    is_test = bool(metadata.get("is_test", False))
    if caller_method is not None:
        owner_type = str(getattr(caller_method, "owner_type", "") or owner_type)
        owner_coord = str(getattr(caller_method, "owner_coord", "") or owner_coord)
        module = str(getattr(caller_method, "module", "") or module)
        is_test = bool(getattr(caller_method, "is_test", is_test))
    if collector == "business_bytecode":
        is_test = False
    owner_type = owner_type or _owner_type(edge.owner_scope)
    owner_coord = owner_coord or edge.owner_coord
    callee_key = str(edge.callee_symbol or "")
    callee_simple_key = (
        str(metadata.get("callee_simple_key") or "")
        or _callee_simple_key(callee_key)
    )
    method_like = (
        callee_simple_key.startswith("method:")
        or "method" in edge.edge_kind
        or "constructor" in edge.edge_kind
    )
    fqcn_complete = bool(
        callee_key.startswith("class:")
        or (
            "." in callee_key.split("(", 1)[0]
            and not callee_key.startswith(("method:", "field:", "invokedynamic:"))
        )
    )
    signature_complete = bool(
        not method_like or ("(" in callee_key and callee_key.endswith(")"))
    )
    if fqcn_complete and signature_complete:
        resolution_note = "调用目标已解析到全限定名和签名"
    elif not fqcn_complete:
        resolution_note = "缺少调用目标所属类全限定名"
    else:
        resolution_note = "缺少调用目标方法参数签名"
    converted = CallEdge(
        caller_symbol_id=caller_symbol,
        caller_qualified_key=caller_qualified_key,
        callee_key=callee_key,
        callee_simple_key=callee_simple_key,
        evidence_type=edge.edge_kind,
        confidence=edge.confidence,
        file=evidence_path,
        line=max(int(edge.provenance.line or 0), 0),
        content=str(metadata.get("content") or ""),
        owner_type=owner_type,
        owner_coord=owner_coord,
        module=module,
        is_test=is_test,
        callee_param_types=list(metadata.get("callee_param_types") or ()),
        callee_signature_complete=signature_complete,
        callee_fqcn_complete=fqcn_complete,
        callee_resolution_note=resolution_note,
    )
    converted.evidence_source = edge.provenance.evidence_source
    converted.artifact_sha256 = edge.provenance.artifact_sha256
    if not converted.artifact_sha256:
        converted.artifact_sha256 = str(metadata.get("artifact_sha256") or "")
    converted.artifact_entry = edge.provenance.artifact_entry
    converted.instruction_offset = edge.provenance.instruction_offset
    converted.evidence_authority = edge.provenance.authority.value
    converted.semantic = edge.semantic
    converted.framework_activation_verified = edge.activation_verified
    converted.activation_evidence = tuple(edge.activation_evidence)
    converted.collector = collector
    converted.evidence_registry_identity = _edge_identity(edge)
    converted.activation_conditions = thaw_evidence_value(edge.activation_conditions)
    converted.ambiguity = edge.ambiguous
    converted.parser = edge.provenance.parser
    return converted


_MYBATIS_PHYSICAL_TARGET_STAGES = {
    (
        "org.apache.ibatis.binding.MapperProxy.invoke"
        "(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])"
    ): "proxy_entry_dispatch",
    (
        "org.apache.ibatis.binding.MapperMethod.execute"
        "(org.apache.ibatis.session.SqlSession,java.lang.Object[])"
    ): "plain_invoker_dispatch",
    (
        "org.apache.ibatis.session.SqlSession.selectOne"
        "(java.lang.String,java.lang.Object)"
    ): "select_one_dispatch",
}

_MYBATIS_TARGET_DESCRIPTORS = {
    "org.apache.ibatis.binding.MapperProxy.invoke": (
        "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)"
        "Ljava/lang/Object;"
    ),
    "org.apache.ibatis.binding.MapperMethod.execute": (
        "(Lorg/apache/ibatis/session/SqlSession;[Ljava/lang/Object;)Ljava/lang/Object;"
    ),
    "org.apache.ibatis.session.SqlSession.selectOne": (
        "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;"
    ),
}

_MYBATIS_DISPATCH_REFS = (
    (
        "org/apache/ibatis/binding/MapperProxy.class",
        "org/apache/ibatis/binding/MapperProxy$MapperMethodInvoker",
        "invoke",
        (
            "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;"
            "Lorg/apache/ibatis/session/SqlSession;)Ljava/lang/Object;"
        ),
    ),
    (
        "org/apache/ibatis/binding/MapperProxy$PlainMethodInvoker.class",
        "org/apache/ibatis/binding/MapperMethod",
        "execute",
        "(Lorg/apache/ibatis/session/SqlSession;[Ljava/lang/Object;)Ljava/lang/Object;",
    ),
    (
        "org/apache/ibatis/binding/MapperMethod.class",
        "org/apache/ibatis/session/SqlSession",
        "selectOne",
        "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;",
    ),
)

def _mybatis_chain_is_complete(edge, edge_mapping, caller):
    metadata = _edge_metadata(edge)
    target = str(edge_mapping.get("target") or "").strip()
    declared_target = str(metadata.get("framework_target") or target).strip()
    provenance = dict(edge_mapping.get("provenance") or {})
    dispatch = provenance.get("verified_dispatch")
    activations = provenance.get("business_activation")
    registration = provenance.get("mapper_registration")
    binding = provenance.get("binding_evidence")
    physical_target = provenance.get("physical_target_evidence")
    final_artifact_sha = str(
        provenance.get("final_artifact_sha256") or ""
    ).lower()
    runtime_sha = str(provenance.get("artifact_sha256") or "").lower()
    runtime_entry = str(provenance.get("artifact_entry") or "").strip()
    expected_dispatch_stage = _MYBATIS_PHYSICAL_TARGET_STAGES.get(target, "")
    source_parameter_count = int(edge_mapping.get("parameter_count") or 0)
    caller_sha = str(getattr(caller, "artifact_sha256", "") or "")
    caller_entry = str(getattr(caller, "artifact_entry", "") or "")
    caller_file = str(getattr(caller, "file", "") or "")
    final_artifact_path = str(
        provenance.get("final_artifact_path") or ""
    ).strip()
    if not final_artifact_path:
        final_artifact_path = str(provenance.get("file") or "").split("!/", 1)[0]
    caller_artifact_path, separator, caller_file_entry = caller_file.partition("!/")
    caller_descriptor = _mybatis_caller_descriptor(
        caller_artifact_path,
        caller_sha,
        (caller_entry, caller_file_entry),
        edge_mapping.get("source_owner"),
        edge_mapping.get("source_member"),
        source_parameter_count,
    )
    activation_is_verified = any(
        isinstance(item, Mapping)
        and str(item.get("artifact_entry") or "").strip()
        and _valid_sha256(item.get("artifact_sha256"))
        and str(item.get("artifact_sha256") or "").lower()
        == final_artifact_sha
        and str(item.get("authority") or "") == "current_final_artifact_classfile"
        and bool(_business_class_entry(item.get("artifact_entry")))
        and _artifact_evidence_matches_bytes(
            item.get("artifact_path") or final_artifact_path,
            final_artifact_sha,
            (item.get("artifact_entry"),),
        )
        and _mybatis_activation_semantics_match(
            item.get("artifact_path") or final_artifact_path,
            final_artifact_sha,
            item.get("artifact_entry"),
        )
        for item in (activations if isinstance(activations, (list, tuple)) else ())
    )
    registration_is_verified = bool(
        isinstance(registration, Mapping)
        and _artifact_evidence_matches_bytes(
            registration.get("artifact_path") or final_artifact_path,
            final_artifact_sha,
            (registration.get("artifact_entry"),),
        )
        and _mybatis_registration_semantics_match(
            registration.get("artifact_path") or final_artifact_path,
            final_artifact_sha,
            registration.get("artifact_entry"),
            edge_mapping.get("source_owner"),
            edge_mapping.get("source_member"),
            caller_descriptor,
        )
    )
    binding_is_verified = bool(
        isinstance(binding, Mapping)
        and _artifact_evidence_matches_bytes(
            binding.get("artifact_path") or final_artifact_path,
            final_artifact_sha,
            (binding.get("artifact_entry"),),
        )
        and _mybatis_binding_semantics_match(
            binding.get("artifact_path") or final_artifact_path,
            final_artifact_sha,
            binding.get("artifact_entry"),
            edge_mapping.get("source_owner"),
            edge_mapping.get("source_member"),
            provenance.get("command"),
            caller_descriptor,
        )
    )
    caller_is_verified = bool(
        caller_entry
        and caller_artifact_path
        and (
            not separator
            or _business_class_entry(caller_file_entry)
            == _business_class_entry(caller_entry)
        )
        and _artifact_evidence_matches_bytes(
            caller_artifact_path,
            caller_sha,
            (caller_entry, caller_file_entry),
        )
        and caller_descriptor
    )
    runtime_is_verified = bool(
        isinstance(physical_target, Mapping)
        and _artifact_evidence_matches_bytes(
            provenance.get("jar"),
            runtime_sha,
            (physical_target.get("class_or_resource_entry"),),
        )
        and _mybatis_runtime_semantics_match(
            provenance.get("jar"), runtime_sha, target
        )
    )
    return bool(
        target
        and expected_dispatch_stage
        and declared_target == target
        and str(edge_mapping.get("source_owner") or "").strip()
        and str(edge_mapping.get("source_member") or "").strip()
        and caller_descriptor
        and str(provenance.get("file") or "").strip()
        and str(provenance.get("binding_file") or "").strip()
        and str(provenance.get("authority") or "") == "final_artifact_javap"
        and _valid_sha256(final_artifact_sha)
        and isinstance(registration, Mapping)
        and str(registration.get("artifact_entry") or "").strip()
        and str(registration.get("authority") or "")
        == "current_final_artifact_classfile"
        and str(registration.get("artifact_sha256") or "").lower()
        == final_artifact_sha
        and registration_is_verified
        and isinstance(binding, Mapping)
        and str(binding.get("artifact_entry") or "").strip()
        and str(binding.get("authority") or "") in {
            "current_final_artifact_classfile",
            "current_final_artifact_resource",
        }
        and str(binding.get("artifact_sha256") or "").lower()
        == final_artifact_sha
        and binding_is_verified
        and runtime_entry
        and _valid_sha256(runtime_sha)
        and isinstance(dispatch, Mapping)
        and all(bool(dispatch.get(stage)) for stage in (
            "proxy_entry_dispatch",
            "plain_invoker_dispatch",
            "select_one_dispatch",
        ))
        and isinstance(physical_target, Mapping)
        and str(physical_target.get("target") or "").strip() == target
        and str(physical_target.get("dispatch_stage") or "")
        == expected_dispatch_stage
        and physical_target.get("verified") is True
        and str(physical_target.get("artifact_entry") or "").strip()
        == runtime_entry
        and str(physical_target.get("artifact_sha256") or "").lower()
        == runtime_sha
        and runtime_is_verified
        and str(getattr(caller, "evidence_source", "") or "")
        == "current_final_artifact"
        and caller_entry
        and _valid_sha256(caller_sha)
        and caller_file
        and (
            "!/" not in caller_file
            or caller_file.split("!/", 1)[1] == caller_entry
        )
        and caller_is_verified
        and activation_is_verified
    )


def _proxy_final_artifact_verified(provenance, caller, *, require_business_sha):
    caller_sha = str(getattr(caller, "artifact_sha256", "") or "").lower()
    caller_entry = str(getattr(caller, "artifact_entry", "") or "").strip()
    business_sha = str(
        provenance.get("business_artifact_sha256") or caller_sha
    ).lower()
    activations = provenance.get("business_activation")
    activation_verified = any(
        isinstance(item, Mapping)
        and _activation_matches_business_artifact(item, business_sha)
        for item in (activations if isinstance(activations, (list, tuple)) else ())
    )
    logical_caller_entry = _business_class_entry(caller_entry)
    caller_file = str(getattr(caller, "file", "") or "").strip()
    caller_artifact_path, separator, caller_file_entry = caller_file.partition("!/")
    caller_verified = bool(
        caller_artifact_path
        and logical_caller_entry
        and (
            not separator
            or _business_class_entry(caller_file_entry) == logical_caller_entry
        )
        and _artifact_evidence_matches_bytes(
            caller_artifact_path,
            caller_sha,
            (
                caller_entry,
                caller_file_entry,
                logical_caller_entry,
                f"BOOT-INF/classes/{logical_caller_entry}",
                f"WEB-INF/classes/{logical_caller_entry}",
            ),
        )
    )
    framework_verified = _artifact_evidence_matches_bytes(
        provenance.get("jar"),
        provenance.get("artifact_sha256"),
        (
            provenance.get("class_or_resource_entry"),
            provenance.get("resource"),
        ),
    )
    return bool(
        str(provenance.get("authority") or "") == "final_artifact_javap"
        and framework_verified
        and _valid_sha256(caller_sha)
        and caller_entry
        and (not require_business_sha or _valid_sha256(
            provenance.get("business_artifact_sha256")
        ))
        and business_sha == caller_sha
        and activation_verified
        and caller_verified
    )


def _activation_matches_business_artifact(activation, business_sha):
    artifact_path = str(activation.get("artifact_path") or "").strip()
    artifact_entry = str(activation.get("artifact_entry") or "").strip()
    business_entry = str(activation.get("business_entry") or "").strip()
    owner = (
        business_entry.rsplit(".", 1)[0]
        if business_entry.endswith(".main")
        else business_entry
    )
    expected_entry = owner.replace(".", "/") + ".class" if owner else ""
    return bool(
        str(activation.get("authority") or "")
        == "current_final_artifact_classfile"
        and _valid_sha256(business_sha)
        and str(activation.get("artifact_sha256") or "").lower() == business_sha
        and artifact_entry
        and expected_entry
        and _business_class_entry(artifact_entry) == expected_entry
        and _artifact_evidence_matches_bytes(
            artifact_path, business_sha, (artifact_entry,)
        )
    )


def _artifact_evidence_matches_bytes(artifact_path, artifact_sha256, entries):
    return _read_artifact_entry_bytes(
        artifact_path, artifact_sha256, entries
    ) is not None


def _read_artifact_entry_bytes(artifact_path, artifact_sha256, entries):
    path = Path(str(artifact_path or ""))
    expected_sha256 = str(artifact_sha256 or "").lower()
    evidence_entries = tuple(str(item or "").strip() for item in entries if item)
    if not path.is_file() or not _valid_sha256(expected_sha256) or not evidence_entries:
        return None
    try:
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != expected_sha256:
            return False
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = set(archive.namelist())
            for entry in evidence_entries:
                if entry in names:
                    return archive.read(entry)
                container_entry, separator, nested_entry = entry.partition("!/")
                if not separator or container_entry not in names or not nested_entry:
                    continue
                try:
                    with zipfile.ZipFile(
                        io.BytesIO(archive.read(container_entry))
                    ) as nested:
                        if nested_entry in set(nested.namelist()):
                            return nested.read(nested_entry)
                except zipfile.BadZipFile:
                    continue
    except (OSError, zipfile.BadZipFile):
        return None
    return None


def _classfile_semantics(data):
    if not data or data[:4] != b"\xca\xfe\xba\xbe":
        return None
    try:
        from business_bytecode_graph import (
            _cp_class_name,
            _cp_name_and_type,
            _parse_classfile_constant_pool,
        )

        cp, offset = _parse_classfile_constant_pool(data)
        if cp is None or offset + 8 > len(data):
            return None
        utf8_values = {
            str(item.get("value") or "")
            for item in cp.values()
            if item.get("tag") == 1
        }
        method_refs = set()
        for item in cp.values():
            if item.get("tag") not in {10, 11}:
                continue
            owner = _cp_class_name(cp, item.get("class_index"))
            name, descriptor = _cp_name_and_type(
                cp, item.get("name_and_type_index")
            )
            method_refs.add((owner, name, descriptor))

        this_class_index = struct.unpack_from(">H", data, offset + 2)[0]
        class_internal_name = _cp_class_name(cp, this_class_index)
        offset += 6
        interface_count = struct.unpack_from(">H", data, offset)[0]
        offset += 2 + interface_count * 2

        def parse_element_value(position):
            if position >= len(data):
                raise ValueError("truncated annotation value")
            tag = chr(data[position])
            position += 1
            if tag in "BCDFIJSZsc":
                return position + 2
            if tag == "e":
                return position + 4
            if tag == "@":
                return parse_annotation(position)[0]
            if tag == "[":
                count = struct.unpack_from(">H", data, position)[0]
                position += 2
                for _ in range(count):
                    position = parse_element_value(position)
                return position
            raise ValueError("unknown annotation value")

        def parse_annotation(position):
            type_index = struct.unpack_from(">H", data, position)[0]
            pair_count = struct.unpack_from(">H", data, position + 2)[0]
            position += 4
            for _ in range(pair_count):
                position += 2
                position = parse_element_value(position)
            descriptor = str((cp.get(type_index) or {}).get("value") or "")
            return position, descriptor

        def parse_annotations(position, length):
            end = position + length
            count = struct.unpack_from(">H", data, position)[0]
            position += 2
            annotations = set()
            for _ in range(count):
                position, descriptor = parse_annotation(position)
                if descriptor:
                    annotations.add(descriptor)
            if position > end:
                raise ValueError("truncated annotation attribute")
            return annotations

        def skip_members(position, *, collect=False):
            count = struct.unpack_from(">H", data, position)[0]
            position += 2
            methods = set()
            method_annotations = {}
            for _ in range(count):
                if position + 8 > len(data):
                    raise ValueError("truncated class member")
                name_index = struct.unpack_from(">H", data, position + 2)[0]
                descriptor_index = struct.unpack_from(">H", data, position + 4)[0]
                attribute_count = struct.unpack_from(">H", data, position + 6)[0]
                method_identity = (
                    str((cp.get(name_index) or {}).get("value") or ""),
                    str((cp.get(descriptor_index) or {}).get("value") or ""),
                )
                if collect:
                    methods.add(method_identity)
                position += 8
                for _attribute in range(attribute_count):
                    if position + 6 > len(data):
                        raise ValueError("truncated class attribute")
                    attribute_name_index = struct.unpack_from(">H", data, position)[0]
                    attribute_name = str(
                        (cp.get(attribute_name_index) or {}).get("value") or ""
                    )
                    length = struct.unpack_from(">I", data, position + 2)[0]
                    if collect and attribute_name in {
                        "RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations",
                    }:
                        method_annotations.setdefault(method_identity, set()).update(
                            parse_annotations(position + 6, length)
                        )
                    position += 6 + length
                    if position > len(data):
                        raise ValueError("truncated class attribute body")
            return position, methods, method_annotations

        offset, _fields, _field_annotations = skip_members(offset)
        offset, methods, method_annotations = skip_members(offset, collect=True)
        class_attribute_count = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        class_annotations = set()
        for _ in range(class_attribute_count):
            if offset + 6 > len(data):
                raise ValueError("truncated class attribute")
            attribute_name_index = struct.unpack_from(">H", data, offset)[0]
            attribute_name = str(
                (cp.get(attribute_name_index) or {}).get("value") or ""
            )
            length = struct.unpack_from(">I", data, offset + 2)[0]
            if attribute_name in {
                "RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations",
            }:
                class_annotations.update(parse_annotations(offset + 6, length))
            offset += 6 + length
            if offset > len(data):
                raise ValueError("truncated class attribute body")
        return {
            "class_internal_name": class_internal_name,
            "class_annotations": class_annotations,
            "utf8": utf8_values,
            "method_refs": method_refs,
            "methods": methods,
            "method_annotations": method_annotations,
        }
    except (ImportError, IndexError, KeyError, struct.error, ValueError):
        return None


def _artifact_class_semantics(artifact_path, artifact_sha256, entries):
    return _classfile_semantics(_read_artifact_entry_bytes(
        artifact_path, artifact_sha256, entries
    ))


def _mybatis_activation_semantics_match(path, sha256, entry):
    content = _read_artifact_entry_bytes(path, sha256, (entry,))
    semantics = _classfile_semantics(content)
    if not semantics:
        return False
    utf8_values = semantics["utf8"]
    if not bool(
        {
            "Lorg/springframework/boot/autoconfigure/SpringBootApplication;",
            "Lorg/springframework/boot/autoconfigure/EnableAutoConfiguration;",
        }
        & utf8_values
        and "org/springframework/boot/SpringApplication" in utf8_values
    ):
        return False
    try:
        from business_bytecode_graph import parse_classfile_calls

        calls = parse_classfile_calls(content, "activation.Application")
    except ImportError:
        return False
    return bool(calls is not None and any(
        str(call.get("caller_name") or "") == "main"
        and str(call.get("caller_descriptor") or "") == "([Ljava/lang/String;)V"
        and str(call.get("callee_jvm_owner") or "")
        == "org.springframework.boot.SpringApplication"
        and str(call.get("callee_descriptor") or "")
        == (
            "(Ljava/lang/Class;[Ljava/lang/String;)"
            "Lorg/springframework/context/ConfigurableApplicationContext;"
        )
        for call in calls
    ))


def _java_type_descriptor(raw_type, owner, *, allow_void=False):
    owner_package = str(owner or "").rpartition(".")[0]
    primitives = {
        "boolean": "Z", "byte": "B", "char": "C", "short": "S",
        "int": "I", "long": "J", "float": "F", "double": "D",
    }
    java_lang = {
        "Boolean", "Byte", "Character", "Short", "Integer", "Long",
        "Float", "Double", "String", "Object", "Class", "Throwable",
    }
    value = re.sub(r"<.*>", "", str(raw_type or "").strip())
    value = value.replace("...", "[]")
    dimensions = 0
    while value.endswith("[]"):
        dimensions += 1
        value = value[:-2].strip()
    if allow_void and value == "void" and not dimensions:
        return "V"
    if value in primitives:
        descriptor = primitives[value]
    else:
        if value in java_lang:
            value = "java.lang." + value
        elif "." not in value and owner_package:
            value = owner_package + "." + value
        if not value or "." not in value:
            return ""
        descriptor = "L" + value.replace(".", "/") + ";"
    return "[" * dimensions + descriptor


def _java_method_descriptor(parameters, return_type, owner):
    if not isinstance(parameters, (list, tuple)):
        return ""
    parameter_descriptors = [
        _java_type_descriptor(item, owner) for item in parameters
    ]
    return_descriptor = _java_type_descriptor(
        return_type, owner, allow_void=True
    )
    if any(not item for item in parameter_descriptors) or not return_descriptor:
        return ""
    return "(" + "".join(parameter_descriptors) + ")" + return_descriptor


def _method_descriptor_matches(methods, member, descriptor):
    return any(
        name == str(member or "")
        and actual_descriptor == str(descriptor or "")
        for name, actual_descriptor in methods
    )


def _mybatis_registration_semantics_match(
    path, sha256, entry, owner, member, descriptor
):
    semantics = _artifact_class_semantics(path, sha256, (entry,))
    return bool(
        semantics
        and semantics["class_internal_name"]
        == str(owner or "").replace(".", "/")
        and "Lorg/apache/ibatis/annotations/Mapper;"
        in semantics["class_annotations"]
        and _method_descriptor_matches(
            semantics["methods"], member, descriptor
        )
    )


def _mybatis_binding_semantics_match(
    path, sha256, entry, owner, member, command, descriptor
):
    content = _read_artifact_entry_bytes(path, sha256, (entry,))
    if not content:
        return False
    if str(entry or "").endswith(".xml"):
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return False
        if str(root.tag).rsplit("}", 1)[-1] != "mapper":
            return False
        if str(root.attrib.get("namespace") or "").strip() != str(owner or ""):
            return False
        return any(
            str(child.tag).rsplit("}", 1)[-1] == str(command or "")
            and str(child.attrib.get("id") or "").strip() == str(member or "")
            for child in root
        )
    semantics = _classfile_semantics(content)
    annotation = str(command or "").strip().capitalize()
    return bool(
        semantics
        and semantics["class_internal_name"]
        == str(owner or "").replace(".", "/")
        and annotation
        and bool(
            set(semantics["method_annotations"].get(
                (str(member or ""), str(descriptor or "")), ()
            ))
            & {
                f"Lorg/apache/ibatis/annotations/{annotation};",
                f"Lorg/apache/ibatis/annotations/{annotation}Provider;",
            }
        )
    )


def _jvm_descriptor_parameter_count(descriptor):
    value = str(descriptor or "")
    if not value.startswith("(") or ")" not in value:
        return -1
    index = 1
    count = 0
    while index < len(value) and value[index] != ")":
        while index < len(value) and value[index] == "[":
            index += 1
        if index >= len(value):
            return -1
        if value[index] == "L":
            end = value.find(";", index)
            if end < 0:
                return -1
            index = end + 1
        elif value[index] in "ZBCSIJFD":
            index += 1
        else:
            return -1
        count += 1
    return count if index < len(value) and value[index] == ")" else -1


def _mybatis_caller_descriptor(
    path, sha256, entries, owner, member, parameter_count
):
    semantics = _artifact_class_semantics(path, sha256, entries)
    expected_owner = str(owner or "").replace(".", "/")
    expected_member = str(member or "")
    if not semantics:
        return ""
    descriptors = {
        ref_descriptor
        for ref_owner, ref_member, ref_descriptor in semantics["method_refs"]
        if (
            ref_owner == expected_owner
            and ref_member == expected_member
            and _jvm_descriptor_parameter_count(ref_descriptor)
            == int(parameter_count)
        )
    }
    return next(iter(descriptors)) if len(descriptors) == 1 else ""


def _mybatis_runtime_semantics_match(path, sha256, target):
    target_name = str(target or "").split("(", 1)[0]
    target_owner, _, target_member = target_name.rpartition(".")
    target_entry = target_owner.replace(".", "/") + ".class"
    target_semantics = _artifact_class_semantics(path, sha256, (target_entry,))
    expected_descriptor = _MYBATIS_TARGET_DESCRIPTORS.get(target_name)
    if not target_semantics or (
        target_member, expected_descriptor
    ) not in target_semantics["methods"]:
        return False
    for (
        class_entry, expected_owner, expected_member, expected_ref_descriptor
    ) in _MYBATIS_DISPATCH_REFS:
        semantics = _artifact_class_semantics(path, sha256, (class_entry,))
        if not semantics or not any(
            owner == expected_owner
            and member == expected_member
            and descriptor == expected_ref_descriptor
            for owner, member, descriptor in semantics["method_refs"]
        ):
            return False
    return True


def _project_mybatis_proxy_edges(graph, records, reverse_edge_snapshot):
    attached = 0
    ambiguous = 0
    for batch, edge, edge_mapping in records:
        if edge.edge_kind != "mybatis_mapper_proxy_dispatch":
            continue
        if (
            edge.ambiguous
            or bool(edge_mapping.get("ambiguity"))
            or int(edge_mapping.get("candidate_count") or 1) > 1
        ):
            ambiguous += 1
            continue
        target = str(edge_mapping.get("target") or "").strip()
        metadata_target = str(
            _edge_metadata(edge).get("framework_target") or target
        ).strip()
        if not target or metadata_target != target:
            continue
        source_identity = (
            str(edge_mapping.get("source_owner") or ""),
            str(edge_mapping.get("source_member") or ""),
            int(edge_mapping.get("parameter_count") or 0),
        )
        source_keys = _source_lookup_keys(reverse_edge_snapshot, source_identity)
        if not source_keys:
            continue
        callers = _ranked_proxy_callers(
            reverse_edge_snapshot,
            source_keys,
            final_artifact_only=True,
        )
        for caller in callers:
            verified = _mybatis_chain_is_complete(edge, edge_mapping, caller)
            confidence = edge.confidence
            if not verified and confidence == "high":
                confidence = "medium"
            synthetic = _proxy_call_edge(
                caller,
                batch,
                edge,
                edge_mapping,
                source_key=source_keys[0],
                target=target,
                evidence_type="mybatis_mapper_proxy_dispatch",
                content_prefix="MyBatis mapper proxy dispatch",
                confidence=confidence,
                final_artifact_verified=verified,
            )
            if _append_call_edge(graph, (target,), synthetic):
                attached += 1
    return attached, ambiguous


def _project_transaction_proxy_edges(graph, records, reverse_edge_snapshot):
    attached = 0
    ambiguous = 0
    for batch, edge, edge_mapping in records:
        if edge.edge_kind != "spring_transaction_proxy_dispatch":
            continue
        if (
            edge.ambiguous
            or bool(edge_mapping.get("ambiguity"))
            or int(edge_mapping.get("candidate_count") or 1) > 1
        ):
            ambiguous += 1
            continue
        source_identity = (
            str(edge_mapping.get("source_owner") or ""),
            str(edge_mapping.get("source_member") or ""),
            int(edge_mapping.get("parameter_count") or 0),
        )
        source_keys = _source_lookup_keys(reverse_edge_snapshot, source_identity)
        target = str(edge_mapping.get("target") or "").strip()
        if not source_keys or not target:
            continue
        provenance = dict(edge_mapping.get("provenance") or {})
        callers = _ranked_proxy_callers(reverse_edge_snapshot, source_keys)
        for caller in callers:
            verified = _proxy_final_artifact_verified(
                provenance, caller, require_business_sha=True,
            )
            confidence = edge.confidence
            if not verified and confidence == "high":
                confidence = "medium"
            synthetic = _proxy_call_edge(
                caller,
                batch,
                edge,
                edge_mapping,
                source_key=source_keys[0],
                target=target,
                evidence_type="spring_transaction_proxy_dispatch",
                content_prefix="Spring transaction proxy dispatch",
                confidence=confidence,
                final_artifact_verified=verified,
                use_framework_line=True,
            )
            if _append_call_edge(graph, _target_lookup_keys(target), synthetic):
                attached += 1
    return attached, ambiguous


def _project_spring_data_proxy_edges(graph, records, reverse_edge_snapshot):
    grouped = {}
    for record in records:
        _batch, edge, edge_mapping = record
        if edge.edge_kind != "spring_data_repository_proxy_dispatch":
            continue
        identity = (
            str(edge_mapping.get("source") or ""),
            str(edge_mapping.get("target_member") or ""),
            int(edge_mapping.get("parameter_count") or 0),
        )
        grouped.setdefault(identity, []).append(record)

    attached = 0
    ambiguous = 0
    for (repository, member, parameter_count), implementation_records in grouped.items():
        source_keys = _source_lookup_keys(
            reverse_edge_snapshot,
            (repository, member, parameter_count),
        )
        declared_method_count = max(
            int(record[2].get("repository_declared_method_count") or 0)
            for record in implementation_records
        )
        explicitly_ambiguous = any(
            record[1].ambiguous
            or bool(record[2].get("ambiguity"))
            or int(record[2].get("candidate_count") or 1) > 1
            for record in implementation_records
        )
        if (
            len(implementation_records) != 1
            or declared_method_count > 1
            or explicitly_ambiguous
        ):
            if source_keys or declared_method_count > 1 or explicitly_ambiguous:
                ambiguous += 1
            continue
        batch, edge, edge_mapping = implementation_records[0]
        target = str(edge_mapping.get("target") or "").strip()
        if not target:
            continue
        callers = _ranked_proxy_callers(reverse_edge_snapshot, source_keys)
        for caller in callers:
            provenance = dict(edge_mapping.get("provenance") or {})
            verified = _proxy_final_artifact_verified(
                provenance, caller, require_business_sha=False,
            )
            confidence = edge.confidence
            if not verified and confidence == "high":
                confidence = "medium"
            synthetic = _proxy_call_edge(
                caller,
                batch,
                edge,
                edge_mapping,
                source_key=source_keys[0],
                target=target,
                evidence_type="spring_data_repository_proxy_dispatch",
                content_prefix="Spring Data repository proxy dispatch",
                confidence=confidence,
                final_artifact_verified=verified,
            )
            if _append_call_edge(graph, _target_lookup_keys(target), synthetic):
                attached += 1
    return attached, ambiguous


def _method_signature(method):
    qualified = str(getattr(method, "qualified_key", "") or "")
    return qualified[qualified.find("("):] if "(" in qualified else ""


def _framework_method_indexes(graph):
    methods = list((getattr(graph, "methods_by_id", {}) or {}).values())
    by_qualified = {}
    by_unsigned = {}
    for method in methods:
        qualified = str(getattr(method, "qualified_key", "") or "")
        if not qualified:
            continue
        by_qualified.setdefault(qualified, []).append(method)
        by_unsigned.setdefault(qualified.split("(", 1)[0], []).append(method)
    return methods, by_qualified, by_unsigned


def _framework_entry_candidates(
    methods,
    methods_by_qualified,
    methods_by_unsigned,
    edge_mapping,
    target,
):
    if edge_mapping.get("edge_kind") == "dubbo_spi_registration":
        interface_methods = [
            method
            for method in methods
            if str(getattr(method, "class_fqcn", "") or "")
            == str(edge_mapping.get("source") or "")
        ]
        candidates = []
        for interface_method in interface_methods:
            interface_name = str(getattr(interface_method, "method_name", "") or "")
            interface_signature = _method_signature(interface_method)
            for method in methods:
                if str(getattr(method, "class_fqcn", "") or "") != target:
                    continue
                if str(getattr(method, "method_name", "") or "") != interface_name:
                    continue
                if interface_signature and _method_signature(method) != interface_signature:
                    continue
                candidates.append(method)
        return candidates

    target_unsigned = target.split("(", 1)[0]
    candidates = list(methods_by_qualified.get(target) or ())
    lookup_key = target_unsigned if target_unsigned != target else target
    for method in methods_by_unsigned.get(lookup_key) or ():
        if method not in candidates:
            candidates.append(method)
    return candidates


def _activation_call_edge(
    batch, edge, edge_mapping, activation_method, callback_key, activation,
):
    provenance = dict(edge_mapping.get("provenance") or {})
    caller_artifact_path = str(activation.get("artifact_path") or "").strip()
    caller_artifact_entry = str(activation.get("artifact_entry") or "").strip()
    caller_artifact_sha = str(activation.get("artifact_sha256") or "").strip()
    caller_file = caller_artifact_path
    if caller_artifact_path and caller_artifact_entry:
        caller_file = f"{caller_artifact_path}!/{caller_artifact_entry}"
    framework_verified = bool(
        _activation_matches_business_artifact(activation, caller_artifact_sha)
        and _valid_sha256(edge.provenance.artifact_sha256)
        and _artifact_evidence_matches_bytes(
            edge.provenance.artifact_path,
            edge.provenance.artifact_sha256,
            (
                edge.provenance.class_or_resource_entry,
                edge.provenance.artifact_entry,
            ),
        )
    )
    caller_evidence_source = (
        "current_final_artifact" if framework_verified else "source_ast"
    )
    values = {
        "caller_symbol_id": getattr(activation_method, "symbol_id", ""),
        "caller_qualified_key": getattr(activation_method, "qualified_key", ""),
        "callee_key": callback_key or str(edge_mapping.get("target") or ""),
        "callee_simple_key": "",
        "evidence_type": "spring_runtime_registered_callback",
        "confidence": "high",
        "file": str(provenance.get("jar") or ""),
        "line": int(provenance.get("line") or 0),
        "content": "Spring Boot 启动后根据当前制品的框架注册触发回调",
        "owner_type": "business",
        "owner_coord": "BUSINESS",
        "module": getattr(activation_method, "module", ""),
        "is_test": False,
        "framework_registration": True,
        "framework_source": edge_mapping.get("source") or "",
        "framework_target": callback_key or edge_mapping.get("target") or "",
        "framework_provenance": provenance,
        "runtime_activation": "active",
        "evidence_source": edge.provenance.evidence_source
        or edge.provenance.authority.value,
        "evidence_authority": edge.provenance.authority.value,
        "artifact_sha256": edge.provenance.artifact_sha256,
        "artifact_entry": edge.provenance.artifact_entry,
        "semantic": True,
        "framework_activation_verified": True,
        "collector": batch.collector,
        "framework_final_artifact_verified": framework_verified,
        "caller_evidence_source": caller_evidence_source,
        "caller_evidence_authority": caller_evidence_source,
        "caller_evidence_type": "spring_boot_activation",
        "caller_artifact_sha256": caller_artifact_sha if framework_verified else "",
        "caller_artifact_entry": caller_artifact_entry if framework_verified else "",
        "caller_evidence_file": (
            caller_file if framework_verified else str(activation.get("file") or "")
        ),
        "caller_evidence_line": 0,
    }
    values.update(_framework_evidence_fields(batch, edge))
    return SimpleNamespace(**values)


def _project_framework_entries(graph, records):
    methods, methods_by_qualified, methods_by_unsigned = _framework_method_indexes(graph)
    entries = {}
    runtime_entries = {}
    activation_linked_symbols = set()
    matched = 0
    unmatched = 0
    final_artifact_mode = bool(
        getattr(graph, "require_current_final_artifact_business_edges", False)
    )

    for batch, edge, edge_mapping in records:
        if edge.edge_kind not in _FRAMEWORK_ENTRY_KINDS:
            continue
        target = str(edge_mapping.get("target") or "").strip()
        if not target:
            unmatched += 1
            continue
        candidates = _framework_entry_candidates(
            methods,
            methods_by_qualified,
            methods_by_unsigned,
            edge_mapping,
            target,
        )
        activations = list(
            (edge_mapping.get("provenance") or {}).get("business_activation")
            or ()
        )
        verified_activations = [
            activation for activation in activations
            if isinstance(activation, Mapping)
            and _activation_matches_business_artifact(
                activation,
                str(activation.get("artifact_sha256") or "").lower(),
            )
        ]
        callback_is_active = bool(
            edge.edge_kind == "spring_runtime_registered_callback"
            and str(edge_mapping.get("runtime_activation") or "") == "active"
            and (verified_activations or not final_artifact_mode)
        )
        runtime_entry_record = None
        if callback_is_active:
            runtime_entry_record = {
                **edge_mapping,
                "adapter": batch.collector,
                "adapter_version": batch.version,
                "activation_verified": bool(verified_activations),
            }
            runtime_entries.setdefault(target.split("(", 1)[0], []).append(
                runtime_entry_record
            )
        if not candidates:
            unmatched += 1
            continue
        for method in candidates:
            entries.setdefault(method.symbol_id, []).append({
                **edge_mapping,
                "adapter": batch.collector,
                "adapter_version": batch.version,
            })
            matched += 1
            if not (
                callback_is_active
            ):
                continue
            active_activations = (
                verified_activations if final_artifact_mode else activations
            )
            for activation in active_activations:
                activation_name = str(
                    (activation or {}).get("business_entry") or ""
                ).strip()
                if not activation_name:
                    continue
                activation_methods = list(
                    methods_by_qualified.get(activation_name) or ()
                )
                activation_methods.extend(
                    item
                    for item in methods_by_unsigned.get(activation_name) or ()
                    if item not in activation_methods
                )
                activation_methods = [
                    item
                    for item in activation_methods
                    if getattr(item, "owner_type", "") == "business"
                    and not getattr(item, "is_test", False)
                ]
                if not activation_methods:
                    continue
                callback_signature = str(
                    getattr(method, "declared_signature", "") or ""
                ).strip()
                callback_key = str(
                    getattr(method, "declared_qualified_key", "") or ""
                ).strip() or (
                    f"{getattr(method, 'qualified_key', '')}{callback_signature}"
                    if callback_signature
                    else str(getattr(method, "qualified_key", "") or "").strip()
                )
                callback_keys = (
                    callback_key,
                    str(getattr(method, "qualified_key", "") or "").strip(),
                    target,
                )
                for activation_method in activation_methods:
                    synthetic = _activation_call_edge(
                        batch,
                        edge,
                        edge_mapping,
                        activation_method,
                        callback_key,
                        activation,
                    )
                    _append_call_edge(graph, callback_keys, synthetic)
                    if runtime_entry_record is not None:
                        runtime_entry_record["activation_verified"] = True
                activation_linked_symbols.add(method.symbol_id)

    graph.framework_entry_symbols = entries
    graph.framework_runtime_entry_methods = runtime_entries
    graph.framework_activation_linked_symbols = activation_linked_symbols
    return {
        "matched_callback_edges": matched,
        "unmatched_callback_edges": unmatched,
        "framework_entry_methods": len(entries),
        "runtime_framework_entry_methods": len(runtime_entries),
        "framework_activation_linked_methods": len(activation_linked_symbols),
    }


def _project_verified_activation_edges(graph, records):
    attached = 0
    for batch, edge, _edge_mapping in records:
        if edge.edge_kind not in {
            "spring_aop_activation", "spring_security_filter_activation",
        }:
            continue
        if (
            not edge.activation_verified
            or not edge.activation_evidence
            or edge.ambiguous
            or edge.activation_conditions
        ):
            continue
        caller_symbol, caller_qualified_key, caller_method = _resolve_caller(graph, edge)
        if caller_symbol is None:
            continue
        converted = _to_call_edge(
            edge,
            batch.collector,
            caller_symbol=caller_symbol,
            caller_qualified_key=caller_qualified_key,
            caller_method=caller_method,
        )
        for key, value in _caller_evidence_fields(caller_method).items():
            setattr(converted, key, value)
        for key, value in _framework_evidence_fields(batch, edge).items():
            setattr(converted, key, value)
        converted.framework_registration = True
        converted.framework_final_artifact_verified = True
        converted.framework_source = edge.caller_symbol
        converted.framework_target = edge.callee_symbol
        converted.framework_provenance = dict(_edge_metadata(edge).get(
            "framework_provenance"
        ) or {})
        if _append_call_edge(
            graph, _target_lookup_keys(edge.callee_symbol), converted
        ):
            attached += 1
    return attached


def _project_framework_edges(graph, records, reverse_edge_snapshot):
    graph.framework_edges = [dict(record[2]) for record in records]
    mybatis_edges, mybatis_ambiguous = _project_mybatis_proxy_edges(
        graph, records, reverse_edge_snapshot
    )
    transaction_edges, transaction_ambiguous = _project_transaction_proxy_edges(
        graph, records, reverse_edge_snapshot
    )
    spring_data_edges, spring_data_ambiguous = _project_spring_data_proxy_edges(
        graph, records, reverse_edge_snapshot
    )
    activation_edges = _project_verified_activation_edges(graph, records)
    stats = _project_framework_entries(graph, records)
    stats.update({
        "framework_proxy_dispatch_edges": spring_data_edges,
        "framework_mybatis_proxy_dispatch_edges": mybatis_edges,
        "framework_transaction_proxy_edges": transaction_edges,
        "framework_activation_edges": activation_edges,
        "ambiguous_framework_proxy_dispatches": (
            mybatis_ambiguous + transaction_ambiguous + spring_data_ambiguous
        ),
    })
    return stats


@dataclass(frozen=True)
class EvidenceRegistry:
    batches: Tuple[CollectorBatch, ...]

    @classmethod
    def from_batches(cls, batches: Iterable[CollectorBatch]):
        normalized = tuple(batches)
        if not all(isinstance(batch, CollectorBatch) for batch in normalized):
            raise ValueError("evidence ingestion accepts CollectorBatch values only")
        return cls(normalized)

    def ingest_into(self, graph) -> IngestionResult:
        if not hasattr(graph, "reverse_edges") or graph.reverse_edges is None:
            graph.reverse_edges = {}
        accepted_edges = []
        framework_records = []
        failures = [
            failure
            for batch in self.batches
            for failure in batch.failures
        ]
        failures_by_collector = [
            (batch.collector, failure)
            for batch in self.batches
            for failure in batch.failures
        ]
        unresolved_failure_positions = {
            (collector, failure.reason_code, failure.api_identity): index
            for index, (collector, failure) in enumerate(failures_by_collector)
            if (
                failure.reason_code == "BYTECODE_CALLER_UNRESOLVED"
                and failure.api_identity
            )
        }
        unresolved_occurrences = {}
        concerns = tuple(
            concern
            for batch in self.batches
            for concern in batch.concerns
        )
        seen = set()
        duplicates = 0
        rejected = 0
        merged_by_collector = {}
        duplicate_by_collector = {}
        rejected_by_collector = {}
        call_edge_identity_index = {}

        def indexed_call_edge_identities(collector, lookup_key):
            cache_key = (collector, lookup_key)
            identities = call_edge_identity_index.get(cache_key)
            if identities is None:
                identities = {
                    _call_edge_identity(existing, collector)
                    for existing in graph.reverse_edges.get(lookup_key, ())
                }
                call_edge_identity_index[cache_key] = identities
            return identities

        def reject_unknown_scope(batch, edge):
            nonlocal rejected
            rejected += 1
            rejected_by_collector[batch.collector] = (
                rejected_by_collector.get(batch.collector, 0) + 1
            )
            failure = EvidenceFailure(
                stage="evidence-ingestion",
                reason_code="EVIDENCE_OWNER_SCOPE_UNKNOWN",
                blocking=True,
                artifact=edge.provenance.artifact_path,
                detail=(
                    f"证据边所有权未知：{edge.caller_symbol} -> {edge.callee_symbol}"
                ),
            )
            failures.append(failure)
            failures_by_collector.append((batch.collector, failure))

        def record_duplicate(batch):
            nonlocal duplicates
            duplicates += 1
            duplicate_by_collector[batch.collector] = (
                duplicate_by_collector.get(batch.collector, 0) + 1
            )

        def record_merge(batch, edge):
            accepted_edges.append(edge)
            merged_by_collector[batch.collector] = (
                merged_by_collector.get(batch.collector, 0) + 1
            )

        def ingest_ordinary_batch(batch):
            nonlocal rejected
            for edge in sorted(batch.edges, key=_edge_identity):
                if edge.owner_scope == ModuleScope.UNKNOWN:
                    reject_unknown_scope(batch, edge)
                    continue
                caller_symbol, caller_qualified_key, caller_method = _resolve_caller(
                    graph, edge
                )
                if caller_symbol is None:
                    rejected += 1
                    rejected_by_collector[batch.collector] = (
                        rejected_by_collector.get(batch.collector, 0) + 1
                    )
                    failure_key = (
                        batch.collector,
                        "BYTECODE_CALLER_UNRESOLVED",
                        edge.callee_symbol,
                    )
                    metadata = _edge_metadata(edge)
                    detail = f"无法将字节码调用方映射到源码方法：{caller_qualified_key}"
                    occurrence = EvidenceFailureOccurrence(
                        caller_symbol=edge.caller_symbol,
                        caller_qualified_key=caller_qualified_key,
                        artifact=edge.provenance.artifact_path,
                        artifact_entry=(
                            edge.provenance.artifact_entry
                            or edge.provenance.class_or_resource_entry
                        ),
                        class_name=str(metadata.get("caller_owner") or ""),
                        line=edge.provenance.line,
                        instruction_offset=edge.provenance.instruction_offset,
                        detail=detail,
                    )
                    unresolved_occurrences.setdefault(failure_key, set()).add(occurrence)
                    continue
                identity = ("ordinary", *_edge_identity(edge))
                if identity in seen:
                    record_duplicate(batch)
                    continue
                seen.add(identity)
                converted = _to_call_edge(
                    edge,
                    batch.collector,
                    caller_symbol=caller_symbol,
                    caller_qualified_key=caller_qualified_key,
                    caller_method=caller_method,
                )
                converted_identity = _call_edge_identity(converted, batch.collector)
                keys = tuple(dict.fromkeys((
                    converted.callee_key,
                    converted.callee_simple_key,
                )))
                if any(
                    converted_identity in indexed_call_edge_identities(
                        batch.collector, key
                    )
                    for key in keys
                ):
                    record_duplicate(batch)
                    continue
                record_merge(batch, edge)
                for key in keys:
                    graph.reverse_edges.setdefault(key, []).append(converted)
                    indexed_call_edge_identities(
                        batch.collector, key
                    ).add(converted_identity)

        framework_batches = tuple(
            batch for batch in self.batches if _is_framework_batch(batch)
        )
        ordinary_batches = tuple(
            batch for batch in self.batches if not _is_framework_batch(batch)
        )
        pre_framework_batches = sorted(
            (
                batch
                for batch in ordinary_batches
                if batch.collector == "business_bytecode"
            ),
            key=lambda item: (item.collector, item.version),
        )
        post_framework_batches = sorted(
            (
                batch
                for batch in ordinary_batches
                if batch.collector != "business_bytecode"
            ),
            key=lambda item: (item.collector, item.version),
        )

        for batch in pre_framework_batches:
            ingest_ordinary_batch(batch)

        replaced_framework_collectors = {
            batch.collector for batch in framework_batches
        }
        all_prior_framework_records = tuple(
            getattr(graph, "step5_framework_records", ()) or ()
        )
        stale_registry_identities = {
            _edge_identity(edge)
            for batch, edge, _mapping in all_prior_framework_records
            if batch.collector in replaced_framework_collectors
        }
        if replaced_framework_collectors:
            for lookup_key, edges in list(graph.reverse_edges.items()):
                retained = [
                    edge for edge in edges
                    if not (
                        str(getattr(edge, "collector", "") or "")
                        in replaced_framework_collectors
                        and bool(getattr(edge, "semantic", False))
                        and bool(getattr(edge, "framework_registration", False))
                    )
                ]
                if retained:
                    graph.reverse_edges[lookup_key] = retained
                else:
                    graph.reverse_edges.pop(lookup_key, None)

        for batch in framework_batches:
            for edge in sorted(
                batch.edges,
                key=lambda item: _framework_edge_identity(batch, item),
            ):
                if edge.owner_scope == ModuleScope.UNKNOWN:
                    reject_unknown_scope(batch, edge)
                    continue
                identity = ("framework", *_framework_edge_identity(batch, edge))
                if identity in seen:
                    record_duplicate(batch)
                    continue
                seen.add(identity)
                record_merge(batch, edge)
                framework_records.append((
                    batch,
                    edge,
                    _framework_edge_mapping(batch, edge),
                ))

        prior_framework_records = tuple(
            record
            for record in all_prior_framework_records
            if record[0].collector not in replaced_framework_collectors
        )
        prior_framework_identities = {
            _framework_edge_identity(batch, edge)
            for batch, edge, _mapping in prior_framework_records
        }
        new_framework_records = []
        for record in framework_records:
            batch, edge, _mapping = record
            identity = _framework_edge_identity(batch, edge)
            if identity not in prior_framework_identities:
                new_framework_records.append(record)
                prior_framework_identities.add(identity)
        graph.step5_framework_records = (
            *prior_framework_records,
            *new_framework_records,
        )
        reverse_edge_snapshot = _snapshot_framework_reverse_edges(
            graph.reverse_edges,
            graph.step5_framework_records,
        )
        framework_stats = _project_framework_edges(
            graph,
            graph.step5_framework_records,
            reverse_edge_snapshot,
        )

        call_edge_identity_index.clear()
        for batch in post_framework_batches:
            ingest_ordinary_batch(batch)

        for failure_key in sorted(unresolved_occurrences):
            collector, reason_code, api_identity = failure_key
            occurrences = tuple(sorted(unresolved_occurrences[failure_key]))
            position = unresolved_failure_positions.get(failure_key)
            if position is None:
                first = occurrences[0]
                failure = EvidenceFailure(
                    stage="evidence-ingestion",
                    reason_code=reason_code,
                    blocking=True,
                    api_identity=api_identity,
                    artifact=first.artifact,
                    class_name=first.class_name,
                    detail=(
                        f"无法将 {len(occurrences)} 个字节码调用方映射到源码方法；"
                        "详见 occurrences"
                    ),
                    occurrences=occurrences,
                )
                failures_by_collector.append((collector, failure))
                unresolved_failure_positions[failure_key] = len(failures_by_collector) - 1
                continue
            existing_collector, existing = failures_by_collector[position]
            failures_by_collector[position] = (
                existing_collector,
                replace(existing, occurrences=(*existing.occurrences, *occurrences)),
            )
        failures = [failure for _collector, failure in failures_by_collector]

        def cumulative(existing, additions):
            merged = list(existing or ())

            def dedupe_key(item):
                try:
                    hash(item)
                except TypeError:
                    return type(item), repr(item)
                return type(item), item

            seen_items = {dedupe_key(item) for item in merged}
            for item in additions:
                item_key = dedupe_key(item)
                if item_key in seen_items:
                    continue
                seen_items.add(item_key)
                merged.append(item)
            return tuple(merged)

        prior_registry = tuple(
            edge
            for edge in (getattr(graph, "step5_evidence_registry", ()) or ())
            if _edge_identity(edge) not in stale_registry_identities
        )
        graph.step5_evidence_registry = cumulative(prior_registry, accepted_edges)
        prior_failures_by_collector = tuple(
            item
            for item in (
                getattr(graph, "step5_evidence_failures_by_collector", ()) or ()
            )
            if item[0] not in replaced_framework_collectors
        )
        graph.step5_evidence_failures_by_collector = cumulative(
            prior_failures_by_collector,
            failures_by_collector,
        )
        graph.step5_evidence_failures = cumulative((), tuple(
            failure
            for _collector, failure in graph.step5_evidence_failures_by_collector
        ))
        prior_concerns_by_collector = tuple(
            item
            for item in (
                getattr(graph, "step5_evidence_concerns_by_collector", ()) or ()
            )
            if item[0] not in replaced_framework_collectors
        )
        graph.step5_evidence_concerns_by_collector = cumulative(
            prior_concerns_by_collector,
            tuple(
                (batch.collector, concern)
                for batch in self.batches
                for concern in batch.concerns
            ),
        )
        graph.step5_evidence_concerns = cumulative((), tuple(
            concern
            for _collector, concern in graph.step5_evidence_concerns_by_collector
        ))
        prior_coverage = tuple(
            coverage
            for coverage in (getattr(graph, "step5_collector_coverage", ()) or ())
            if coverage.collector not in replaced_framework_collectors
        )
        graph.step5_collector_coverage = cumulative(
            prior_coverage,
            tuple(
            coverage
            for batch in self.batches
            for coverage in batch.coverage
            ),
        )
        return IngestionResult(
            merged_edges=len(accepted_edges),
            duplicate_edges=duplicates,
            rejected_edges=rejected,
            failures=tuple(failures),
            merged_by_collector=tuple(sorted(merged_by_collector.items())),
            duplicate_by_collector=tuple(sorted(duplicate_by_collector.items())),
            rejected_by_collector=tuple(sorted(rejected_by_collector.items())),
            failures_by_collector=tuple(failures_by_collector),
            **framework_stats,
        )


def ingest_collector_batches(graph, batches: Iterable[CollectorBatch]) -> IngestionResult:
    """Validate and merge all post-source evidence through one boundary."""
    return EvidenceRegistry.from_batches(batches).ingest_into(graph)


__all__ = [
    "EvidenceRegistry",
    "IngestionResult",
    "ingest_collector_batches",
]
