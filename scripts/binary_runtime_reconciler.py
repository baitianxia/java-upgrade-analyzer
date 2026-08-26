#!/usr/bin/env python3
"""Target-runtime provider, definition, member-resolution and dispatch view."""

from __future__ import annotations

from collections.abc import Collection, Iterator
from dataclasses import dataclass, field, replace
from functools import lru_cache
import json
from typing import Any, Iterable, Mapping

from artifact_safety import is_jar_signature_block_entry
from binary_definition_verifier import (
    ClassDefinitionVerifierError,
    verifier_identity,
    verify_class_definitions,
)
from binary_fact_store import (
    BinaryFactStore,
    LOADING_CONSTRAINT_TYPE_OWNERS_KEY,
)
from binary_first_contract import (
    BinaryFirstContractError,
    StreamingCanonicalSequence,
    canonical_identity_native_json,
    canonical_identity_streaming,
)
from binary_first_model import (
    RuntimeProfile,
    _class_definition_resolution_identity_native,
    _dispatch_resolution_identity_native,
    _member_resolution_identity_native,
    _provider_binding_identity_native,
)
from binary_platform_image import JdkPlatformImage, PlatformClassFact


ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_INTERFACE = 0x0200
ACC_ABSTRACT = 0x0400
MIN_MULTI_RELEASE_VERSION = 8
MIN_MULTI_RELEASE_RUNTIME_MAJOR = 9

# Runtime edge payloads are canonical fact-store JSON and are commonly shared
# by millions of ordinary bytecode references. Cache only bounded payloads:
# bootstrap constants can contain arbitrarily large nested arguments and must
# never turn this CPU optimization into an unbounded residency increase.
_EDGE_JSON_CACHE_MAX_ENTRIES = 16_384
_EDGE_JSON_CACHE_MAX_VALUE_BYTES = 16 * 1024

# Symbolic resolution is a pure function once definition evidence has been
# built. Real applications repeatedly call a much smaller common API surface
# from millions of call sites, so a bounded root-resolution cache removes the
# repeated hierarchy walks without retaining the complete edge population.
_SYMBOLIC_MEMBER_CACHE_MAX_ENTRIES = 16_384


class RuntimeReconciliationError(BinaryFirstContractError):
    pass


class _StoreClassBytes(Mapping[str, bytes]):
    """Lazy mapping used by the verifier to cap Python classfile residency."""

    def __init__(
        self,
        store: BinaryFactStore,
        variants_by_name: Mapping[str, str],
    ):
        self.store = store
        self.variants_by_name = dict(variants_by_name)

    def __getitem__(self, name: str) -> bytes:
        return self.store.class_bytes(self.variants_by_name[name])

    def __iter__(self) -> Iterator[str]:
        return iter(self.variants_by_name)

    def __len__(self) -> int:
        return len(self.variants_by_name)


_MISSING_COMPACT_VALUE = object()


class _CompactRow(Mapping[str, Any]):
    """Tuple-backed immutable row for large reconciliation indexes."""

    __slots__ = ("_values",)
    FIELDS: tuple[str, ...] = ()
    INDEX: Mapping[str, int] = {}

    def __init__(self, values: Iterable[Any]):
        values = tuple(values)
        if len(values) != len(self.FIELDS):
            raise RuntimeReconciliationError(
                "RUNTIME_COMPACT_ROW_SHAPE_INVALID",
                f"{type(self).__name__}: {len(values)} != {len(self.FIELDS)}",
            )
        self._values = values

    def __getitem__(self, key: str) -> Any:
        try:
            value = self._values[self.INDEX[key]]
        except KeyError as error:
            raise KeyError(key) from error
        if value is _MISSING_COMPACT_VALUE:
            raise KeyError(key)
        return value

    def __iter__(self) -> Iterator[str]:
        return (
            field for field, value in zip(self.FIELDS, self._values)
            if value is not _MISSING_COMPACT_VALUE
        )

    def __len__(self) -> int:
        return sum(
            value is not _MISSING_COMPACT_VALUE for value in self._values
        )

    def __or__(self, other: Mapping[str, Any]) -> dict[str, Any]:
        return dict(self) | dict(other)

    def __ror__(self, other: Mapping[str, Any]) -> dict[str, Any]:
        return dict(other) | dict(self)


class _ClassRow(_CompactRow):
    FIELDS = (
        "class_variant_identity", "artifact_instance_identity", "class_name",
        "class_major", "multi_release_version", "parse_status", "failure_kind",
        "class_access", "super_name", "interfaces", "nest_host", "nest_members",
    )
    INDEX = {name: index for index, name in enumerate(FIELDS)}


class _MemberRow(_CompactRow):
    FIELDS = (
        "member_identity", "class_variant_identity", "class_name",
        "member_kind", "member_name", "descriptor", "access_flags",
    )
    INDEX = {name: index for index, name in enumerate(FIELDS)}


class _ProviderRuntimeRow(_CompactRow):
    """Provider fields still consulted after complete evidence is persisted."""

    FIELDS = (
        "runtime_profile_identity",
        "initiating_loader_realm_identity",
        "class_name",
        "class_provider_status",
        "provider_binding_identity",
        "selected_defining_loader_realm_identity",
        "selected_artifact_instance_identity",
        "selected_class_variant_identity",
        "provider_equivalence_set_identity",
    )
    INDEX = {name: index for index, name in enumerate(FIELDS)}


class _DefinitionRuntimeRow(_CompactRow):
    """Definition fields still consulted while resolving runtime edges."""

    FIELDS = (
        "initiating_loader_realm_identity",
        "class_name",
        "class_definition_status",
        "class_load_status",
        "class_definition_resolution_identity",
        "provider_binding_identity",
    )
    INDEX = {name: index for index, name in enumerate(FIELDS)}


def _shared_string(value: Any, pool: dict[str, str]) -> Any:
    if type(value) is not str:
        return value
    return pool.setdefault(value, value)


def _shared_string_tuple_json(
    value: str, pool: dict[str, str],
) -> tuple[str, ...]:
    if value == "[]":
        return ()
    return tuple(
        _shared_string(item, pool) for item in json.loads(value)
    )


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity_native_json(
        namespace, payload, schema_version="1"
    )


def _type_provider_owner(symbolic_owner: str) -> str:
    """Return the defining class needed to resolve a JVM type owner."""
    value = str(symbolic_owner or "")
    if not value.startswith("["):
        return value
    while value.startswith("["):
        value = value[1:]
    if value.startswith("L") and value.endswith(";"):
        return value[1:-1]
    # Primitive array classes are created by the JVM and have no classfile
    # provider. Their original array descriptor remains on the direct edge.
    return ""


def class_load_is_ready(definition: Mapping[str, Any] | None) -> bool:
    """Whether the JVM loaded the class before any member-enumeration failure.

    A missing type used only by an unrelated field or method can make
    ``getDeclaredMethods`` fail even though ``Class.forName(..., false, ...)``
    succeeded. Callback discovery, hierarchy traversal and dispatch need the
    latter fact; conclusions that require complete reflective enumeration keep
    using ``class_definition_status``.
    """
    if not definition:
        return False
    if definition.get("class_load_status") == "ready":
        return True
    if definition.get("class_definition_status") == "definition_ready":
        return True
    outcome = (
        (definition.get("evidence") or {}).get("target_jvm_verification")
        or {}
    )
    return outcome.get("failure_phase") == "member_linkage"


def _loads(value: str) -> Any:
    return json.loads(value or "{}")


@lru_cache(maxsize=_EDGE_JSON_CACHE_MAX_ENTRIES)
def _load_small_edge_json(value: str) -> Any:
    """Decode one trusted, bounded fact-store edge payload.

    Callers treat the returned JSON tree as immutable. Keeping this cache
    separate from generic resource JSON prevents large XML/resource semantic
    payloads from surviving the reconciliation phase merely because they were
    decoded once.
    """
    return json.loads(value)


def _load_edge_json(value: str) -> Any:
    normalized = str(value or "{}")
    # Four bytes per Unicode scalar is the conservative UTF-8 bound. Avoid
    # allocating encoded bytes merely to decide whether a hot payload may be
    # cached.
    if len(normalized) <= _EDGE_JSON_CACHE_MAX_VALUE_BYTES // 4:
        return _load_small_edge_json(normalized)
    return json.loads(normalized)


def _loading_constraint_type_owners(
    payload: Mapping[str, Any],
) -> tuple[str, ...]:
    value = payload.get(LOADING_CONSTRAINT_TYPE_OWNERS_KEY)
    if value is None:
        return ()
    if not isinstance(value, list) or not value or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise RuntimeReconciliationError(
            "RUNTIME_LOADING_CONSTRAINT_FACT_INVALID",
            f"{LOADING_CONSTRAINT_TYPE_OWNERS_KEY} must be a non-empty string list",
        )
    normalized = tuple(value)
    if normalized != tuple(sorted(set(normalized))):
        raise RuntimeReconciliationError(
            "RUNTIME_LOADING_CONSTRAINT_FACT_INVALID",
            f"{LOADING_CONSTRAINT_TYPE_OWNERS_KEY} must be sorted and unique",
        )
    return normalized


@lru_cache(maxsize=_EDGE_JSON_CACHE_MAX_ENTRIES)
def _loading_constraint_type_owners_from_edge_json(
    value: str,
) -> tuple[str, ...]:
    """Decode and validate the canonical descriptor-owner declaration once."""
    return _loading_constraint_type_owners(_load_edge_json(value))


def _package(class_name: str) -> str:
    return class_name.rpartition("/")[0]


@dataclass(frozen=True)
class RuntimeCapabilityPolicy:
    supported_loader_policy_versions: tuple[str, ...] = ("flat-parent-first-v1",)
    supported_delegation_modes: tuple[str, ...] = ("parent_first",)
    supported_security_policy_identities: tuple[str, ...] = (
        "standard-unsealed-unsigned-v1",
    )
    supported_module_modes: tuple[str, ...] = ("unnamed",)
    supported_transformer_profile_identities: tuple[str, ...] = ()
    signed_artifacts_supported: bool = False
    sealed_packages_supported: bool = False
    closed_world_dispatch: bool = True
    policy_version: str = "binary-runtime-capability-v2"
    identity: str = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "identity", _identity(
            "runtime_reconciliation_capability_identity",
            {
                "supported_loader_policy_versions": list(self.supported_loader_policy_versions),
                "supported_delegation_modes": list(self.supported_delegation_modes),
                "supported_security_policy_identities": list(self.supported_security_policy_identities),
                "supported_module_modes": list(self.supported_module_modes),
                "supported_transformer_profile_identities": list(self.supported_transformer_profile_identities),
                "signed_artifacts_supported": self.signed_artifacts_supported,
                "sealed_packages_supported": self.sealed_packages_supported,
                "closed_world_dispatch": self.closed_world_dispatch,
                "policy_version": self.policy_version,
            },
        ))


@dataclass(frozen=True)
class RuntimeReconciliationResult:
    analysis_context_identity: str
    runtime_profile_identity: str
    universe_identity: str
    provider_bindings: Collection[dict[str, Any]]
    class_definitions: Collection[dict[str, Any]]
    member_resolutions: Collection[dict[str, Any]]
    dispatch_resolutions: Collection[dict[str, Any]]
    type_resolutions: Collection[dict[str, Any]]
    class_initialization_resolutions: Collection[dict[str, Any]]
    linkage_resolutions: Collection[dict[str, Any]]
    resource_selections: Collection[dict[str, Any]]
    coverage_status: str
    coverage_gaps: tuple[str, ...]
    identity: str


_RECONCILIATION_RECORD_FIELDS = {
    "provider_binding": (
        "class_provider_status", "provider_binding_identity",
    ),
    "class_definition": (
        "class_definition_status", "class_definition_resolution_identity",
    ),
    "member_resolution": (
        "member_resolution_status", "member_resolution_identity",
    ),
    "dispatch_resolution": (
        "dispatch_status", "dispatch_resolution_identity",
    ),
    "type_resolution": (
        "type_resolution_status", "type_resolution_identity",
    ),
    "class_initialization_resolution": (
        "class_initialization_status",
        "class_initialization_resolution_identity",
    ),
    "linkage_resolution": (
        "linkage_status", "linkage_resolution_identity",
    ),
    "resource_selection": (
        "resource_selection_status", "resource_selection_identity",
    ),
}

_RECONCILIATION_RESULT_FIELDS_BY_KIND = {
    "provider_binding": "provider_bindings",
    "class_definition": "class_definitions",
    "member_resolution": "member_resolutions",
    "dispatch_resolution": "dispatch_resolutions",
    "type_resolution": "type_resolutions",
    "class_initialization_resolution": "class_initialization_resolutions",
    "linkage_resolution": "linkage_resolutions",
    "resource_selection": "resource_selections",
}


class _PersistedReconciliationPayloads(Collection[dict[str, Any]]):
    """Repeatable, store-backed view over one reconciliation record family."""

    __slots__ = ("store", "record_kind", "_count")

    def __init__(self, store: BinaryFactStore, record_kind: str):
        self.store = store
        self.record_kind = str(record_kind)
        counter = getattr(store, "reconciliation_payload_count", None)
        self._count = (
            int(counter(self.record_kind))
            if callable(counter)
            else sum(1 for _item in store.reconciliation_payloads(
                self.record_kind
            ))
        )

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.store.reconciliation_payloads(self.record_kind))

    def __len__(self) -> int:
        return self._count

    def __contains__(self, candidate: object) -> bool:
        return any(item == candidate for item in self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Iterable):
            return False
        sentinel = object()
        left = iter(self)
        right = iter(other)
        while True:
            left_item = next(left, sentinel)
            right_item = next(right, sentinel)
            if left_item is sentinel or right_item is sentinel:
                return left_item is sentinel and right_item is sentinel
            if left_item != right_item:
                return False


def hydrate_runtime_reconciliation(
    store: BinaryFactStore,
    reconciliation: RuntimeReconciliationResult,
    record_kinds: Iterable[str],
) -> RuntimeReconciliationResult:
    """Restore exact persisted record families omitted from the Python view.

    Selective reconciliation controls transient memory only; SQLite remains the
    complete authority. Downstream phases must explicitly hydrate every family
    they consume so the optimization cannot silently turn absent memory into
    absent analysis evidence.
    """
    if not isinstance(reconciliation, RuntimeReconciliationResult):
        # Preserve support for test doubles and callers predating selective
        # retention. They have no persisted hydration contract.
        return reconciliation
    requested = {str(kind) for kind in record_kinds}
    unknown = requested - set(_RECONCILIATION_RESULT_FIELDS_BY_KIND)
    if unknown:
        raise RuntimeReconciliationError(
            "RUNTIME_RECONCILIATION_HYDRATION_KIND_INVALID",
            f"unknown reconciliation hydration kinds: {sorted(unknown)}",
        )
    replacements = {}
    for kind in sorted(requested):
        field_name = _RECONCILIATION_RESULT_FIELDS_BY_KIND[kind]
        if getattr(reconciliation, field_name):
            continue
        persisted = _PersistedReconciliationPayloads(store, kind)
        if persisted:
            replacements[field_name] = persisted
    return replace(reconciliation, **replacements) if replacements else reconciliation


class _CompactIdentitySequence:
    """Store SHA-256 identities at 32 bytes each until canonical hashing."""

    DIGEST_BYTES = 32

    def __init__(self):
        self._digests = bytearray()

    def append(self, identity: str) -> None:
        value = str(identity or "")
        try:
            digest = bytes.fromhex(value)
        except ValueError as error:
            raise RuntimeReconciliationError(
                "RUNTIME_RECONCILIATION_SUBJECT_IDENTITY_INVALID", value
            ) from error
        if len(digest) != self.DIGEST_BYTES or digest.hex() != value:
            raise RuntimeReconciliationError(
                "RUNTIME_RECONCILIATION_SUBJECT_IDENTITY_INVALID", value
            )
        self._digests.extend(digest)

    def _iter_identities(self) -> Iterator[str]:
        for offset in range(0, len(self._digests), self.DIGEST_BYTES):
            yield self._digests[offset:offset + self.DIGEST_BYTES].hex()

    def canonical_sequence(self) -> StreamingCanonicalSequence:
        return StreamingCanonicalSequence(self._iter_identities)


class _ReconciliationAccumulator:
    """Persist reconciliation evidence in bounded chunks.

    Some consumers need only a subset of the records in Python.  The complete
    evidence remains in SQLite for the independent Oracle, while unneeded
    record dictionaries are released after each chunk instead of remaining
    resident until the whole runtime has been reconciled.
    """

    CHUNK_SIZE = 2_000

    def __init__(
        self,
        store: BinaryFactStore,
        analysis_context_identity: str,
        retained_kinds: Iterable[str],
    ):
        self.store = store
        self.analysis_context_identity = analysis_context_identity
        self.retained_kinds = frozenset(retained_kinds)
        unknown = self.retained_kinds - set(_RECONCILIATION_RECORD_FIELDS)
        if unknown:
            raise RuntimeReconciliationError(
                "RUNTIME_RECONCILIATION_RETAINED_KIND_INVALID",
                f"unknown retained reconciliation kinds: {sorted(unknown)}",
            )
        self.records = {
            kind: [] for kind in _RECONCILIATION_RECORD_FIELDS
        }
        # Retained records already own their identity strings, so a list stores
        # only references. For unretained evidence, keeping millions of Python
        # strings solely for the final result identity is wasteful; compact the
        # fixed SHA-256 values to 32 bytes and expose them lazily to the exact
        # canonical streaming encoder.
        self.subject_identities = {
            kind: [] if kind in self.retained_kinds else _CompactIdentitySequence()
            for kind in _RECONCILIATION_RECORD_FIELDS
        }
        self.pending = {
            kind: [] for kind in _RECONCILIATION_RECORD_FIELDS
        }

    def add(self, kind: str, record: dict[str, Any]) -> None:
        status_key, identity_key = _RECONCILIATION_RECORD_FIELDS[kind]
        self.subject_identities[kind].append(record[identity_key])
        if kind in self.retained_kinds:
            self.records[kind].append(record)
        pending = self.pending[kind]
        pending.append((
            record[status_key],
            record[identity_key],
            record,
        ))
        if len(pending) >= self.CHUNK_SIZE:
            self._flush_kind(kind)

    def _flush_kind(self, kind: str) -> None:
        pending = self.pending[kind]
        if not pending:
            return
        self.store.add_reconciliation_payloads(
            analysis_context_identity=self.analysis_context_identity,
            record_kind=kind,
            records=pending,
            collect_identities=False,
            manage_transaction=False,
        )
        pending.clear()

    def flush(self) -> None:
        for kind in _RECONCILIATION_RECORD_FIELDS:
            self._flush_kind(kind)

    def canonical_subject_identities(
        self, kind: str
    ) -> list[str] | StreamingCanonicalSequence:
        identities = self.subject_identities[kind]
        if isinstance(identities, _CompactIdentitySequence):
            return identities.canonical_sequence()
        return identities


class RuntimeReconciler:
    DIRECT_EDGE_SCAN_ORDER = "rowid"

    def __init__(
        self,
        store: BinaryFactStore,
        runtime_profile: RuntimeProfile,
        platform: JdkPlatformImage,
        *,
        analysis_context_identity: str,
        capability_policy: RuntimeCapabilityPolicy | None = None,
        additional_initial_classes: Iterable[str] = (),
    ):
        self.store = store
        self.profile = runtime_profile
        self.platform = platform
        self.context_identity = str(analysis_context_identity or "")
        self.capability = capability_policy or RuntimeCapabilityPolicy()
        self.additional_initial_classes = tuple(sorted({
            str(name) for name in additional_initial_classes if str(name)
        }))
        if not self.context_identity:
            raise RuntimeReconciliationError(
                "RUNTIME_RECONCILIATION_CONTEXT_MISSING", "analysis context is required"
            )
        payload = dict(runtime_profile.payload)
        if payload.get("runtime_platform_image_identity") != platform.identity:
            raise RuntimeReconciliationError(
                "RUNTIME_PLATFORM_IMAGE_IDENTITY_MISMATCH",
                "runtime profile does not bind the supplied platform image",
            )
        target = payload.get("target_jvm") or {}
        target_major = int(target.get("major") or 0) if isinstance(target, Mapping) else 0
        if target_major != platform.java_major:
            raise RuntimeReconciliationError(
                "RUNTIME_TARGET_JVM_PLATFORM_MISMATCH",
                f"profile major={target_major}; platform major={platform.java_major}",
            )
        self.target_java_major = target_major
        self.target_class_major = target_major + 44
        shared_strings: dict[str, str] = {}
        self.artifacts = {
            row["artifact_instance_identity"]: row
            for row in store.rows(
                "artifact_instances",
                where="runtime_profile_identity=?",
                parameters=(runtime_profile.identity,),
            )
        }
        for artifact_identity in self.artifacts:
            shared_strings[artifact_identity] = artifact_identity
        # Runtime selection needs only these seven scalar fields.  The generic
        # metadata reader also materializes physical labels and content/contract
        # digests for every class, retaining several unused Python strings per
        # row across the whole reconciliation phase.
        self.classes = [
            _ClassRow((
                _shared_string(row[0], shared_strings),
                _shared_string(row[1], shared_strings),
                _shared_string(row[2], shared_strings),
                row[3],
                row[4],
                _shared_string(row[5], shared_strings),
                _shared_string(row[6], shared_strings),
                row[7],
                _shared_string(row[8], shared_strings),
                _shared_string_tuple_json(row[9], shared_strings),
                _shared_string(row[10], shared_strings),
                _shared_string_tuple_json(row[11], shared_strings),
            ))
            for row in store.connection.execute(
                """
                SELECT class_variant_identity,artifact_instance_identity,
                       class_name,class_major,multi_release_version,
                       parse_status,failure_kind,class_access,super_name,
                       interfaces_json,nest_host,nest_members_json
                FROM classes
                """
            )
        ]
        self.class_by_variant = {row["class_variant_identity"]: row for row in self.classes}
        self.members_by_variant: dict[str, list[Mapping[str, Any]]] = {}
        self.member_by_identity: dict[str, Mapping[str, Any]] = {}
        for raw in store.connection.execute(
            """
            SELECT member_identity,class_variant_identity,class_name,
                   member_kind,member_name,descriptor,access_flags
            FROM members
            """
        ):
            row = _MemberRow((
                raw[0],
                _shared_string(raw[1], shared_strings),
                _shared_string(raw[2], shared_strings),
                _shared_string(raw[3], shared_strings),
                _shared_string(raw[4], shared_strings),
                _shared_string(raw[5], shared_strings),
                raw[6],
            ))
            self.members_by_variant.setdefault(row["class_variant_identity"], []).append(row)
            self.member_by_identity[row["member_identity"]] = row
        # Every pooled value is now owned by at least one compact row. The
        # construction dictionary itself would only duplicate those references
        # throughout reconciliation, so release it before provider graphs grow.
        shared_strings.clear()
        self.realms, self.entrypoint_realms, topology_gaps = self._loader_topology(payload)
        self.coverage_gaps = set(topology_gaps)
        # RuntimeProfile validates that every required field has an explicit
        # coverage value before reconciliation can be constructed.
        profile_coverage = dict(payload["field_coverage"])
        for field_name in RuntimeProfile.REQUIRED_FIELDS:
            if profile_coverage.get(field_name) == "unknown":
                self.coverage_gaps.add(f"runtime_profile_field_unknown:{field_name}")
        if payload.get("resource_selection_coverage_status") != "complete":
            self.coverage_gaps.add("resource_selection_scope_incomplete")
        self.provider_bindings: dict[
            tuple[str, str], Mapping[str, Any]
        ] = {}
        self.definition_records: dict[
            tuple[str, str], Mapping[str, Any]
        ] = {}
        self.class_info_cache: dict[tuple[str, str], dict[str, Any] | None] = {}
        self.ancestor_type_cache: dict[tuple[str, str], frozenset[str]] = {}
        self.virtual_dispatch_cache: dict[
            tuple[str, str, str], tuple[str, ...]
        ] = {}
        self._symbolic_member_root_cache: dict[
            tuple[str, str, str, str, str],
            tuple[Mapping[str, Any] | None, Mapping[str, Any] | None],
        ] = {}
        self._symbolic_member_cache_hits = 0
        self._symbolic_member_cache_misses = 0
        self.artifact_manifest_cache: dict[str, dict[str, list[str]]] = {}
        self.artifact_security_unsupported_cache: dict[str, bool] = {}
        self.concrete_subtype_cache: dict[
            str, tuple[tuple[str, str], ...]
        ] = {}
        self.concrete_subtype_index_built = False
        for artifact_id, artifact in self.artifacts.items():
            if artifact["coverage_status"] != "complete":
                self.coverage_gaps.add(f"artifact_fact_coverage_incomplete:{artifact_id}")
        self.effective_candidates = self._effective_class_candidates()
        resource_rows = [
            row for row in self.store.rows("resources")
            if row["artifact_instance_identity"] in self.artifacts
        ]
        self.resource_categories_by_name: dict[str, set[str]] = {}
        self.resource_candidates_by_realm_name: dict[
            tuple[str, str], list[dict[str, Any]]
        ] = {}
        for row in resource_rows:
            name = row["resource_name"]
            artifact = self.artifacts[row["artifact_instance_identity"]]
            realm = artifact["loader_realm_identity"]
            self.resource_categories_by_name.setdefault(name, set()).add(
                row["resource_category"]
            )
            self.resource_candidates_by_realm_name.setdefault(
                (realm, name), []
            ).append(row)
        for rows in self.resource_candidates_by_realm_name.values():
            rows.sort(key=lambda row: (
                self.artifacts[row["artifact_instance_identity"]][
                    "runtime_classpath_index"
                ],
                row["artifact_instance_identity"],
                row["physical_entry_identity"],
            ))

    def _loader_topology(self, payload: Mapping[str, Any]):
        topology = payload.get("loader_topology") or {}
        realms = {}
        entrypoints = []
        gaps = []
        if isinstance(topology, Mapping) and isinstance(topology.get("realms"), list):
            for raw in topology["realms"]:
                if not isinstance(raw, Mapping) or not raw.get("identity"):
                    gaps.append("loader_topology_invalid_realm")
                    continue
                realms[str(raw["identity"])] = dict(raw)
            entrypoints = [str(item) for item in topology.get("entrypoint_realms") or ()]
            if topology.get("coverage_status") != "complete":
                gaps.append("loader_topology_coverage_incomplete")
        elif isinstance(topology, Mapping):
            for identity, raw in topology.items():
                if isinstance(raw, Mapping):
                    realms[str(identity)] = {"identity": str(identity), **dict(raw)}
            entrypoints = [
                identity for identity, raw in realms.items()
                if raw.get("entrypoint", identity in {"application", "application-loader"})
            ]
        if not realms:
            gaps.append("loader_topology_missing")
        artifact_realms = {row["loader_realm_identity"] for row in self.artifacts.values()}
        for realm in artifact_realms:
            if realm not in realms:
                gaps.append(f"loader_realm_undeclared:{realm}")
        if not entrypoints:
            entrypoints = sorted(artifact_realms)
        for identity, realm in realms.items():
            declared_parent = str(realm.get("parent") or "")
            if declared_parent and declared_parent not in realms:
                gaps.append(
                    f"loader_parent_undeclared:{identity}:{declared_parent}"
                )
            if realm.get("delegation", "parent_first") not in self.capability.supported_delegation_modes:
                gaps.append(f"loader_delegation_unsupported:{identity}")
            if (
                realm.get("kind") != "platform"
                and realm.get("module_mode", "unnamed") not in self.capability.supported_module_modes
            ):
                gaps.append(f"module_mode_unsupported:{identity}")
        # A finite topology is mandatory; cycles cannot be resolved by timestamp/order guesses.
        for identity in realms:
            seen = {identity}
            parent = str(realms[identity].get("parent") or "")
            while parent and parent in realms:
                if parent in seen:
                    raise RuntimeReconciliationError(
                        "LOADER_TOPOLOGY_CYCLE", f"loader cycle contains {parent}"
                    )
                seen.add(parent)
                parent = str(realms[parent].get("parent") or "")
        return realms, tuple(entrypoints), gaps

    def _artifact_manifest(self, artifact_identity: str) -> dict[str, list[str]]:
        cached = self.artifact_manifest_cache.get(artifact_identity)
        if cached is not None:
            return cached
        rows = self.store.rows(
            "archive_entries",
            where="artifact_instance_identity=? AND upper(name)='META-INF/MANIFEST.MF'",
            parameters=(artifact_identity,),
        )
        result: dict[str, list[str]] = {}
        for row in rows:
            for key, value in _loads(row["resource_semantic_json"]):
                result.setdefault(str(key).lower(), []).append(str(value))
        self.artifact_manifest_cache[artifact_identity] = result
        return result

    def _effective_class_candidates(self) -> dict[str, dict[str, list[dict[str, Any]]]]:
        by_artifact: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for row in self.classes:
            artifact_id = row["artifact_instance_identity"]
            if artifact_id not in self.artifacts or row["class_name"] == "module-info":
                continue
            by_artifact.setdefault(artifact_id, {}).setdefault(row["class_name"], []).append(row)
        by_realm: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for artifact_id, classes in by_artifact.items():
            artifact = self.artifacts[artifact_id]
            manifest = self._artifact_manifest(artifact_id)
            mr_values = [item.lower() for item in manifest.get("multi-release", [])]
            mr_enabled = len(mr_values) == 1 and mr_values[0] == "true"
            if len(mr_values) > 1:
                self.coverage_gaps.add(f"manifest_multi_release_ambiguous:{artifact_id}")
            if artifact["container_loader_policy_version"] not in self.capability.supported_loader_policy_versions:
                self.coverage_gaps.add(f"container_loader_policy_unsupported:{artifact_id}")
            realm = artifact["loader_realm_identity"]
            for class_name, variants in classes.items():
                applicable = [
                    row for row in variants
                    if row["multi_release_version"] == 0
                    or (
                        mr_enabled
                        and self.target_java_major >= MIN_MULTI_RELEASE_RUNTIME_MAJOR
                        and MIN_MULTI_RELEASE_VERSION
                        <= row["multi_release_version"]
                        <= self.target_java_major
                    )
                ]
                if not applicable:
                    continue
                highest = max(row["multi_release_version"] for row in applicable)
                selected = [row for row in applicable if row["multi_release_version"] == highest]
                if len(selected) != 1:
                    self.coverage_gaps.add(
                        f"class_variant_ambiguous:{artifact_id}:{class_name}:{highest}"
                    )
                for row in selected:
                    by_realm.setdefault(realm, {}).setdefault(class_name, []).append(row)
        for realm_classes in by_realm.values():
            for candidates in realm_classes.values():
                candidates.sort(key=lambda row: (
                    self.artifacts[row["artifact_instance_identity"]]["runtime_classpath_index"],
                    row["artifact_instance_identity"],
                ))
        return by_realm

    @staticmethod
    def _resource_mechanism(name: str, category: str) -> str:
        if category == "runtime_topology" or name.startswith("META-INF/services/"):
            return "ordered_all"
        return "classloader_first"

    def _own_resource_candidates(self, realm: str, name: str) -> list[dict[str, Any]]:
        return list(self.resource_candidates_by_realm_name.get((realm, name), ()))

    def _selected_resources(
        self,
        initiating_realm: str,
        name: str,
        mechanism: str,
        stack: tuple[tuple[str, str, str], ...] = (),
    ) -> tuple[list[dict[str, Any]], list[str]]:
        key = (initiating_realm, name, mechanism)
        if key in stack:
            raise RuntimeReconciliationError(
                "RESOURCE_SELECTION_CYCLE", f"resource selection cycle for {key}"
            )
        realm = self.realms.get(initiating_realm)
        if not realm or realm.get("kind") == "platform":
            # The supported unnamed-classpath profile has no JAR-style platform
            # resource candidates. Named-module service discovery is deliberately
            # outside this mechanism and is rejected by the module-mode gate.
            return [], []
        parent = str(realm.get("parent") or self._platform_realm())
        delegation = str(realm.get("delegation") or "parent_first")
        parent_rows, parent_gaps = self._selected_resources(
            parent, name, mechanism, stack + (key,)
        )
        own_rows = self._own_resource_candidates(initiating_realm, name)
        ordered = (
            [*parent_rows, *own_rows]
            if delegation == "parent_first"
            else [*own_rows, *parent_rows]
        )
        gaps = list(parent_gaps)
        if mechanism == "classloader_first":
            ordered = ordered[:1]
        return ordered, gaps

    def _resource_selections(self) -> tuple[dict[str, Any], ...]:
        names = sorted(self.resource_categories_by_name)
        records = []
        for realm in self.entrypoint_realms:
            for name in names:
                categories = self.resource_categories_by_name[name]
                category = next(iter(categories)) if len(categories) == 1 else "unknown"
                mechanism = self._resource_mechanism(name, category)
                selected, gaps = self._selected_resources(realm, name, mechanism)
                if len(categories) != 1:
                    gaps.append("resource_category_ambiguous")
                if category == "unknown":
                    gaps.append("resource_semantics_unregistered")
                selected_records = []
                for row in selected:
                    artifact = self.artifacts[row["artifact_instance_identity"]]
                    selected_records.append({
                        "physical_entry_identity": row["physical_entry_identity"],
                        "artifact_instance_identity": row["artifact_instance_identity"],
                        "runtime_classpath_index": artifact["runtime_classpath_index"],
                        "runtime_code_source_origin_identity": artifact[
                            "runtime_code_source_origin_identity"
                        ],
                        "content_sha256": row["content_sha256"],
                        "normalized_resource_digest": row["normalized_resource_digest"],
                        "resource_semantic_facts": _loads(row["resource_semantic_json"]),
                    })
                status = "resolved" if selected_records else "missing"
                coverage = "complete" if not gaps else "partial"
                payload = {
                    "runtime_profile_identity": self.profile.identity,
                    "initiating_loader_realm_identity": realm,
                    "resource_name": name,
                    "resource_category": category,
                    "resource_mechanism": mechanism,
                    "resource_selection_status": status,
                    "selected_resources": selected_records,
                    "coverage_status": coverage,
                    "coverage_gaps": sorted(set(gaps)),
                }
                payload["resource_selection_identity"] = _identity(
                    "resource_selection_identity", payload
                )
                records.append(payload)
        return tuple(records)

    def _platform_realm(self) -> str:
        for identity, realm in self.realms.items():
            if realm.get("kind") == "platform":
                return identity
        return "platform"

    def _provider(self, initiating_realm: str, class_name: str, stack=()) -> dict[str, Any]:
        key = (initiating_realm, class_name)
        if key in self.provider_bindings:
            return self.provider_bindings[key]
        if key in stack:
            raise RuntimeReconciliationError(
                "PROVIDER_RESOLUTION_CYCLE", f"provider cycle for {key}"
            )
        platform_realm = self._platform_realm()
        if initiating_realm == platform_realm or initiating_realm not in self.realms:
            platform_fact = self.platform.get_class(class_name)
            if platform_fact is None:
                record = self._provider_record(
                    initiating_realm, class_name, "missing", evidence={"source": "target_platform_image"}
                )
            else:
                record = self._provider_record(
                    initiating_realm,
                    class_name,
                    "resolved",
                    selected_loader=platform_realm,
                    selected_artifact=f"platform-image:{self.platform.identity}:{platform_fact.module_name}",
                    selected_variant=platform_fact.class_variant_identity,
                    evidence={"source": "target_platform_image", "module": platform_fact.module_name},
                )
            self.provider_bindings[key] = record
            return record

        realm = self.realms[initiating_realm]
        parent = str(realm.get("parent") or platform_realm)
        delegation = realm.get("delegation", "parent_first")
        own = self.effective_candidates.get(initiating_realm, {}).get(class_name, [])

        def own_record():
            if not own:
                return None
            first_slot = self.artifacts[own[0]["artifact_instance_identity"]]["runtime_classpath_index"]
            tied = [
                row for row in own
                if self.artifacts[row["artifact_instance_identity"]]["runtime_classpath_index"] == first_slot
            ]
            if len(tied) != 1:
                return self._provider_record(
                    initiating_realm,
                    class_name,
                    "ambiguous",
                    evidence={"candidate_class_variant_identities": [row["class_variant_identity"] for row in tied]},
                )
            selected = tied[0]
            return self._provider_record(
                initiating_realm,
                class_name,
                "resolved",
                selected_loader=initiating_realm,
                selected_artifact=selected["artifact_instance_identity"],
                selected_variant=selected["class_variant_identity"],
                evidence={
                    "delegation": delegation,
                    "runtime_classpath_index": first_slot,
                    "candidate_class_variant_identities": [row["class_variant_identity"] for row in own],
                },
            )

        parent_record = None
        if delegation == "parent_first":
            parent_record = self._provider(parent, class_name, stack + (key,))
            if parent_record["class_provider_status"] != "missing":
                self.provider_bindings[key] = parent_record | {
                    "initiating_loader_realm_identity": initiating_realm,
                    "provider_binding_identity": _identity(
                        "delegated_provider_binding_identity",
                        {
                            "initiating_loader_realm_identity": initiating_realm,
                            "parent_provider_binding_identity": parent_record["provider_binding_identity"],
                        },
                    ),
                }
                return self.provider_bindings[key]
        selected_own = own_record()
        if selected_own is not None:
            self.provider_bindings[key] = selected_own
            return selected_own
        if delegation == "child_first":
            parent_record = self._provider(parent, class_name, stack + (key,))
            if parent_record["class_provider_status"] != "missing":
                self.provider_bindings[key] = parent_record | {
                    "initiating_loader_realm_identity": initiating_realm,
                    "provider_binding_identity": _identity(
                        "delegated_provider_binding_identity",
                        {
                            "initiating_loader_realm_identity": initiating_realm,
                            "parent_provider_binding_identity": parent_record["provider_binding_identity"],
                        },
                    ),
                }
                return self.provider_bindings[key]
        record = self._provider_record(
            initiating_realm, class_name, "missing", evidence={"delegation": delegation}
        )
        self.provider_bindings[key] = record
        return record

    def _provider_record(
        self,
        initiating_realm: str,
        class_name: str,
        status: str,
        *,
        selected_loader: str = "",
        selected_artifact: str = "",
        selected_variant: str = "",
        evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        payload = {
            "runtime_profile_identity": self.profile.identity,
            "initiating_loader_realm_identity": initiating_realm,
            "class_name": class_name,
            "class_provider_status": status,
            "selection_evidence": dict(evidence),
        }
        if status == "resolved":
            payload.update({
                "selected_defining_loader_realm_identity": selected_loader,
                "selected_artifact_instance_identity": selected_artifact,
                "selected_class_variant_identity": selected_variant,
            })
        payload["provider_binding_identity"] = _provider_binding_identity_native(payload)
        return payload

    def _universe(self) -> tuple[tuple[str, str], ...]:
        initial_classes = {
            row["class_name"] for row in self.classes
            if row["artifact_instance_identity"] in self.artifacts
            and row["class_name"] != "module-info"
        }
        initial_classes.update(
            owner
            for row in self.store.connection.execute(
                """
                SELECT DISTINCT edge.symbolic_owner
                FROM direct_edges AS edge
                JOIN artifact_instances AS artifact
                  ON artifact.artifact_instance_identity =
                     edge.caller_artifact_instance_identity
                WHERE artifact.runtime_profile_identity=?
                  AND edge.symbolic_owner<>''
                """,
                (self.profile.identity,),
            )
            for owner in (_type_provider_owner(row["symbolic_owner"]),)
            if owner
        )
        loading_constraint_classes: set[str] = set()
        for row in self.store.connection.execute(
            """
            SELECT edge.edge_json
            FROM direct_edges AS edge
            JOIN artifact_instances AS artifact
              ON artifact.artifact_instance_identity =
                 edge.caller_artifact_instance_identity
            WHERE artifact.runtime_profile_identity=?
              AND (
                edge.edge_kind IN (
                'method','field','invokedynamic_bootstrap',
                'ldc_constant_dynamic_bootstrap','ldc_handle'
                )
                OR edge.edge_kind LIKE 'invokedynamic_handle_%'
                OR edge.edge_kind LIKE 'ldc_bootstrap_handle_%'
              )
            """,
            (self.profile.identity,),
        ):
            loading_constraint_classes.update(
                _loading_constraint_type_owners_from_edge_json(
                    str(row["edge_json"] or "{}")
                )
            )
        initial_classes.update(
            name for name in self.additional_initial_classes if name != "module-info"
        )
        # ``_provider`` may ask the platform image about every symbolic owner.
        # Resolve the whole initial frontier as one framed ASM batch instead of
        # launching a helper process once per previously unseen JDK class.
        self.platform.ensure_classes(initial_classes)
        contexts = set()
        pending = [
            (realm, name)
            for realm in self.entrypoint_realms
            for name in initial_classes
        ]
        # A loading constraint compares the class identity selected by both
        # the caller's defining loader and the actual declaration's defining
        # loader. Materialize the finite provider matrix once so edge
        # reconciliation remains dictionary-only and cannot create untracked
        # provider records after the universe has been persisted.
        pending.extend(
            (realm, name)
            for realm in self.realms
            for name in loading_constraint_classes
        )
        while pending:
            realm, name = pending.pop()
            if (realm, name) in contexts:
                continue
            contexts.add((realm, name))
            provider = self._provider(realm, name)
            if provider["class_provider_status"] != "resolved":
                continue
            fact = self._class_fact(provider)
            if not fact:
                continue
            defining = provider["selected_defining_loader_realm_identity"]
            for dependency in [fact.get("super_name"), *(fact.get("interfaces") or ())]:
                if dependency and (defining, dependency) not in contexts:
                    pending.append((defining, dependency))
        return tuple(sorted(contexts))

    def _class_fact(self, provider: Mapping[str, Any]) -> dict[str, Any] | None:
        variant = provider.get("selected_class_variant_identity")
        fact = self.class_by_variant.get(str(variant or ""))
        if fact:
            return fact
        for name in (provider.get("class_name"),):
            platform_fact = self.platform.get_class(str(name or ""))
            if platform_fact and platform_fact.class_variant_identity == variant:
                return platform_fact.fact
        return None

    def _definition_status_from_failure(self, failure_kind: str) -> str:
        kind = str(failure_kind or "")
        if "UnsupportedClassVersion" in kind:
            return "unsupported_class_version"
        if "ClassFormat" in kind:
            return "class_format_error"
        if any(token in kind for token in ("NoClassDefFound", "ClassNotFound", "TypeNotPresent")):
            return "dependency_linkage_failed"
        if "IllegalAccess" in kind or "InaccessibleObject" in kind:
            return "module_access_failed"
        return "verification_failed"

    def _build_definitions(
        self,
        universe: Iterable[tuple[str, str]],
        accumulator: _ReconciliationAccumulator,
    ) -> None:
        selected_by_realm: dict[str, dict[str, str]] = {}
        for realm, name in universe:
            provider = self._provider(realm, name)
            if provider["class_provider_status"] != "resolved":
                continue
            variant = provider["selected_class_variant_identity"]
            row = self.class_by_variant.get(variant)
            if row and row["parse_status"] == "parsed":
                # Verify through the initiating realm, not only through the
                # defining realm. A child loader may link one of its classes
                # against a provider selected from an explicitly declared
                # parent realm. The verification input must therefore contain
                # the complete effective provider view seen by that child.
                selected_by_realm.setdefault(realm, {})[name] = str(variant)
        # Keep each verifier result map under its realm instead of copying all
        # entries into another tuple-keyed dictionary. Records are popped as
        # they are persisted below, so complete target-JVM evidence is never
        # retained in two whole-runtime maps at once.
        verified_by_realm: dict[str, dict[str, Any]] = {}
        for realm, selected in selected_by_realm.items():
            current = realm
            seen = set()
            supported_parent_first = True
            while current and current != self._platform_realm():
                if current in seen:
                    supported_parent_first = False
                    break
                seen.add(current)
                realm_config = self.realms.get(current)
                if realm_config is None:
                    supported_parent_first = False
                    break
                if (
                    realm_config.get("delegation", "parent_first")
                    != "parent_first"
                    or realm_config.get("module_mode", "unnamed") != "unnamed"
                ):
                    supported_parent_first = False
                    break
                current = str(
                    realm_config.get("parent") or self._platform_realm()
                )
            if not supported_parent_first or current != self._platform_realm():
                self.coverage_gaps.add(f"definition_topology_unsupported:{realm}")
                continue
            try:
                outcomes = verify_class_definitions(
                    self.platform,
                    _StoreClassBytes(self.store, selected),
                )
            except ClassDefinitionVerifierError as error:
                self.coverage_gaps.add(f"definition_verifier_failed:{realm}:{error.reason_code}")
                continue
            verified_by_realm[realm] = outcomes

        security_identity = str(
            self.profile.payload.get("runtime_security_and_package_sealing_policy_identity") or ""
        )
        security_supported = security_identity in self.capability.supported_security_policy_identities
        transformers = tuple(
            self.profile.payload.get("agent_transformer_plugin_profile_identities") or ()
        )
        transformers_supported = set(transformers) <= set(
            self.capability.supported_transformer_profile_identities
        )
        for realm, name in universe:
            provider = self._provider(realm, name)
            status = provider["class_provider_status"]
            evidence: dict[str, Any] = {
                "provider_binding_identity": provider["provider_binding_identity"],
                "target_class_major": self.target_class_major,
                "runtime_platform_image_identity": self.platform.identity,
            }
            if status == "ambiguous":
                definition_status = "ambiguous"
            elif status != "resolved":
                definition_status = "unsupported"
            else:
                variant = provider["selected_class_variant_identity"]
                row = self.class_by_variant.get(variant)
                if row is None:
                    definition_status = "definition_ready"
                    evidence["verification"] = "target_platform_image"
                elif row["parse_status"] != "parsed":
                    definition_status = "class_format_error"
                    evidence["parse_failure_kind"] = row["failure_kind"]
                elif int(row["class_major"] or 0) > self.target_class_major:
                    definition_status = "unsupported_class_version"
                elif not security_supported:
                    definition_status = "security_failed"
                    evidence["reason"] = "runtime_security_policy_unsupported"
                elif self._artifact_security_unsupported(row["artifact_instance_identity"]):
                    definition_status = "security_failed"
                    evidence["reason"] = "signed_or_sealed_artifact_unsupported"
                elif not transformers_supported:
                    definition_status = "unsupported"
                    evidence["reason"] = "transformer_profile_unsupported"
                else:
                    outcome = verified_by_realm.get(realm, {}).pop(name, None)
                    if outcome is None:
                        definition_status = "unsupported"
                        evidence["reason"] = "target_jvm_verification_unavailable"
                    else:
                        if outcome["status"] == "definition_ready":
                            definition_status = "definition_ready"
                        elif outcome["status"] == "verification_unavailable":
                            definition_status = "unsupported"
                            self.coverage_gaps.add(
                                f"definition_verifier_budget_exhausted:{realm}"
                            )
                        else:
                            definition_status = self._definition_status_from_failure(
                                outcome.get("failure_kind", "")
                            )
                        evidence["target_jvm_verification"] = outcome
            resolution_identity = _class_definition_resolution_identity_native(
                provider["provider_binding_identity"],
                str(provider.get("selected_class_variant_identity") or name),
                definition_status,
                evidence,
            )
            record = {
                "initiating_loader_realm_identity": realm,
                "class_name": name,
                "class_definition_status": definition_status,
                "class_load_status": (
                    "ready"
                    if definition_status == "definition_ready"
                    or (
                        (evidence.get("target_jvm_verification") or {}).get(
                            "failure_phase"
                        )
                        == "member_linkage"
                    )
                    else "failed"
                ),
                "class_definition_resolution_identity": resolution_identity,
                "provider_binding_identity": provider["provider_binding_identity"],
                "evidence": evidence,
            }
            accumulator.add("class_definition", record)
            self.definition_records[(realm, name)] = record
            if "class_definition" not in accumulator.retained_kinds:
                self.definition_records[(realm, name)] = _DefinitionRuntimeRow(
                    record[field]
                    for field in _DefinitionRuntimeRow.FIELDS
                )

    def _compact_persisted_runtime_records(
        self, retained_kinds: frozenset[str] | set[str]
    ) -> None:
        """Release full records that SQLite or the result tuple already owns.

        Edge resolution needs only a small scalar subset of provider and
        definition evidence. Replacing cache values in place releases each
        full dictionary before constructing the next compact row, avoiding a
        second whole-cache residency spike. When callers request a family in
        the returned result, its accumulator list keeps the exact dictionaries
        and compaction is skipped because it would only add another view.
        """
        if "provider_binding" not in retained_kinds:
            for key, record in self.provider_bindings.items():
                self.provider_bindings[key] = _ProviderRuntimeRow(
                    (
                        record[field]
                        if field in record else _MISSING_COMPACT_VALUE
                    )
                    for field in _ProviderRuntimeRow.FIELDS
                )
        if "class_definition" not in retained_kinds:
            for key, record in self.definition_records.items():
                self.definition_records[key] = _DefinitionRuntimeRow(
                    (
                        record[field]
                        if field in record else _MISSING_COMPACT_VALUE
                    )
                    for field in _DefinitionRuntimeRow.FIELDS
                )

    def _artifact_security_unsupported(self, artifact_identity: str) -> bool:
        cached = self.artifact_security_unsupported_cache.get(artifact_identity)
        if cached is not None:
            return cached
        resources = self.store.rows(
            "resources",
            where="artifact_instance_identity=? AND resource_category='operational_security'",
            parameters=(artifact_identity,),
        )
        has_signature_block_candidate = any(
            is_jar_signature_block_entry(row.get("resource_name"))
            for row in resources
        )
        if (
            has_signature_block_candidate
            and not self.capability.signed_artifacts_supported
        ):
            unsupported = True
        else:
            manifest = self._artifact_manifest(artifact_identity)
            sealed = any(
                value.lower() == "true" for value in manifest.get("sealed", ())
            )
            unsupported = sealed and not self.capability.sealed_packages_supported
        self.artifact_security_unsupported_cache[artifact_identity] = unsupported
        return unsupported

    @staticmethod
    def _class_load_ready(definition: Mapping[str, Any] | None) -> bool:
        return class_load_is_ready(definition)

    def _class_info(self, provider: Mapping[str, Any]) -> dict[str, Any] | None:
        cache_key = (
            str(provider.get("selected_defining_loader_realm_identity") or ""),
            str(provider.get("selected_class_variant_identity") or ""),
        )
        if cache_key in self.class_info_cache:
            return self.class_info_cache[cache_key]
        fact = self._class_fact(provider)
        if fact is None:
            self.class_info_cache[cache_key] = None
            return None
        variant = provider["selected_class_variant_identity"]
        row = self.class_by_variant.get(variant)
        if row:
            members = self.members_by_variant.get(variant, [])
            module_name = ""
        else:
            platform_fact = self.platform.get_class(provider["class_name"])
            if platform_fact is None:
                return None
            module_name = platform_fact.module_name
            members = []
            for kind, items in (("field", fact.get("fields") or ()), ("method", fact.get("methods") or ())):
                for item in items:
                    contract = item if kind == "field" else item.get("contract") or {}
                    members.append({
                        "member_identity": _identity(
                            "platform_member_identity",
                            {
                                "platform_class_variant_identity": variant,
                                "member_kind": kind,
                                "name": contract.get("name"),
                                "descriptor": contract.get("descriptor"),
                            },
                        ),
                        "class_variant_identity": variant,
                        "class_name": fact.get("class_name"),
                        "member_kind": kind,
                        "member_name": contract.get("name"),
                        "descriptor": contract.get("descriptor"),
                        "access_flags": int(contract.get("access") or 0),
                    })
        result = {
            "class_name": fact.get("class_name"),
            "class_variant_identity": variant,
            "defining_loader_realm_identity": provider["selected_defining_loader_realm_identity"],
            "access_flags": int(fact.get("class_access") or 0),
            "super_name": fact.get("super_name"),
            "interfaces": tuple(fact.get("interfaces") or ()),
            "nest_host": str(fact.get("nest_host") or ""),
            "nest_members": tuple(str(value) for value in fact.get("nest_members") or ()),
            "module_name": module_name,
            "members": members,
        }
        self.class_info_cache[cache_key] = result
        return result

    def _resolve_symbolic_member_root(
        self,
        initiating_realm: str,
        owner: str,
        kind: str,
        name: str,
        descriptor: str,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        return self._resolve_symbolic_member_uncached(
            initiating_realm, owner, kind, name, descriptor, ()
        )

    def _resolve_symbolic_member(
        self,
        initiating_realm: str,
        owner: str,
        kind: str,
        name: str,
        descriptor: str,
        visited=(),
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if not visited:
            key = (initiating_realm, owner, kind, name, descriptor)
            try:
                cached = self._symbolic_member_root_cache.pop(key)
            except KeyError:
                self._symbolic_member_cache_misses += 1
                cached = self._resolve_symbolic_member_root(*key)
                if len(self._symbolic_member_root_cache) >= (
                    _SYMBOLIC_MEMBER_CACHE_MAX_ENTRIES
                ):
                    oldest = next(iter(self._symbolic_member_root_cache))
                    del self._symbolic_member_root_cache[oldest]
            else:
                self._symbolic_member_cache_hits += 1
            # Pop/reinsert makes the ordinary insertion-ordered dict a bounded
            # LRU without wrapping a bound method. A functools wrapper stored
            # on self would create a reference cycle retaining the reconciler's
            # complete class/member indexes until cyclic GC.
            self._symbolic_member_root_cache[key] = cached
            return cached
        return self._resolve_symbolic_member_uncached(
            initiating_realm, owner, kind, name, descriptor, visited
        )

    def _resolve_symbolic_member_uncached(
        self,
        initiating_realm: str,
        owner: str,
        kind: str,
        name: str,
        descriptor: str,
        visited=(),
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if (initiating_realm, owner) in visited:
            return None, None
        provider = self._provider(initiating_realm, owner)
        definition = self.definition_records.get((initiating_realm, owner))
        if (
            provider["class_provider_status"] != "resolved"
            or not self._class_load_ready(definition)
        ):
            return None, provider
        info = self._class_info(provider)
        if info is None:
            return None, provider
        for member in info["members"]:
            if (
                member["member_kind"] == kind
                and member["member_name"] == name
                and member["descriptor"] == descriptor
            ):
                return member, provider
        next_visited = visited + ((initiating_realm, owner),)
        defining = info["defining_loader_realm_identity"]
        if kind == "field":
            parents = [*info["interfaces"], info["super_name"]]
        elif name == "<init>":
            parents = []
        elif int(info.get("access_flags") or 0) & ACC_INTERFACE:
            # JVMS 5.4.3.4 admits an Object fallback only for a public,
            # non-static method. Do not traverse the interface classfile's
            # ``super_name=java/lang/Object`` as an ordinary superclass.
            object_member, object_provider = self._resolve_symbolic_member_uncached(
                defining,
                "java/lang/Object",
                kind,
                name,
                descriptor,
                next_visited,
            )
            if object_member:
                flags = int(object_member.get("access_flags") or 0)
                if flags & ACC_PUBLIC and not flags & ACC_STATIC:
                    return object_member, object_provider
            parents = [*info["interfaces"]]
        else:
            parents = [info["super_name"], *info["interfaces"]]
        for parent in parents:
            if not parent:
                continue
            resolved, resolved_provider = self._resolve_symbolic_member_uncached(
                defining, parent, kind, name, descriptor, next_visited
            )
            if resolved:
                return resolved, resolved_provider
        return None, provider

    def _ancestor_types(
        self, realm: str, child: str, visiting=(),
    ) -> frozenset[str]:
        key = (realm, child)
        cached = self.ancestor_type_cache.get(key)
        if cached is not None:
            return cached
        if key in visiting:
            return frozenset({child})
        provider = self._provider(realm, child)
        info = self._class_info(provider) if provider.get("class_provider_status") == "resolved" else None
        if not info:
            result = frozenset({child})
            self.ancestor_type_cache[key] = result
            return result
        defining = info["defining_loader_realm_identity"]
        ancestors = {child}
        for candidate in [info["super_name"], *info["interfaces"]]:
            if candidate:
                ancestors.update(
                    self._ancestor_types(defining, candidate, visiting + (key,))
                )
        result = frozenset(ancestors)
        self.ancestor_type_cache[key] = result
        return result

    def _is_subtype(self, realm: str, child: str, parent: str, visited=()) -> bool:
        # ``visited`` remains accepted for callers compiled against the former
        # recursive API; the cached transitive closure is independent of it.
        return parent in self._ancestor_types(realm, child)

    def _virtual_dispatch_targets(
        self,
        universe: Iterable[tuple[str, str]],
        owner: str,
        name: str,
        descriptor: str,
    ) -> tuple[str, ...]:
        key = (owner, name, descriptor)
        cached = self.virtual_dispatch_cache.get(key)
        if cached is not None:
            return cached
        if not self.concrete_subtype_index_built:
            # Build the inverse hierarchy once. The former lazy implementation
            # rescanned the complete runtime universe for every distinct virtual
            # owner, turning large dependency closures into O(classes * owners).
            concrete_by_ancestor: dict[str, list[tuple[str, str]]] = {}
            for candidate_realm, candidate_name in universe:
                candidate_definition = self.definition_records.get(
                    (candidate_realm, candidate_name)
                )
                if (
                    not candidate_definition
                    or not self._class_load_ready(candidate_definition)
                ):
                    continue
                candidate_provider = self._provider(candidate_realm, candidate_name)
                info = self._class_info(candidate_provider)
                if not info or info["access_flags"] & (ACC_INTERFACE | ACC_ABSTRACT):
                    continue
                candidate = (candidate_realm, candidate_name)
                for ancestor in self._ancestor_types(
                    candidate_realm, candidate_name
                ):
                    concrete_by_ancestor.setdefault(ancestor, []).append(candidate)
            self.concrete_subtype_cache = {
                ancestor: tuple(sorted(candidates))
                for ancestor, candidates in concrete_by_ancestor.items()
            }
            self.concrete_subtype_index_built = True
        candidates = self.concrete_subtype_cache.get(owner, ())
        targets = set()
        for candidate_realm, candidate_name in candidates:
            target, _ = self._resolve_symbolic_member(
                candidate_realm, candidate_name, "method", name, descriptor
            )
            if target:
                targets.add(target["member_identity"])
        result = tuple(sorted(targets))
        self.virtual_dispatch_cache[key] = result
        return result

    def _member_accessible(
        self,
        caller_class: str,
        caller_realm: str,
        member: Mapping[str, Any],
        provider: Mapping[str, Any],
    ) -> bool:
        flags = int(member["access_flags"])
        owner = str(member["class_name"])
        defining = str(provider["selected_defining_loader_realm_identity"])
        if flags & ACC_PUBLIC:
            info = self._class_info(provider)
            if info and info["module_name"]:
                exports = self.platform.module_exports().get(info["module_name"], frozenset())
                return _package(owner) in exports
            return True
        if flags & ACC_PRIVATE:
            return (
                caller_class == owner and caller_realm == defining
            ) or self._validated_nestmates(
                caller_class, caller_realm, owner, defining
            )
        same_runtime_package = caller_realm == defining and _package(caller_class) == _package(owner)
        if flags & ACC_PROTECTED:
            return same_runtime_package or self._is_subtype(caller_realm, caller_class, owner)
        return same_runtime_package

    def _validated_nestmates(
        self,
        caller_class: str,
        caller_realm: str,
        owner: str,
        owner_realm: str,
    ) -> bool:
        """Apply JVMS nestmate private-access rules to selected runtime classes.

        A matching ``NestHost`` name alone is insufficient: both classes must
        be in the same runtime package/loader and the selected host must list
        every non-host member in its ``NestMembers`` attribute.  This mirrors
        the JVM's fail-closed validation for malformed or shadowed nest data.
        """
        if (
            not caller_class
            or not owner
            or caller_realm != owner_realm
            or _package(caller_class) != _package(owner)
        ):
            return False

        caller_provider = self._provider(caller_realm, caller_class)
        owner_provider = self._provider(owner_realm, owner)
        if (
            caller_provider.get("class_provider_status") != "resolved"
            or owner_provider.get("class_provider_status") != "resolved"
        ):
            return False
        caller_info = self._class_info(caller_provider)
        owner_info = self._class_info(owner_provider)
        if not caller_info or not owner_info:
            return False
        caller_host = str(caller_info.get("nest_host") or caller_class)
        owner_host = str(owner_info.get("nest_host") or owner)
        if caller_host != owner_host:
            return False

        host_provider = self._provider(caller_realm, caller_host)
        host_definition = self.definition_records.get((caller_realm, caller_host))
        if (
            host_provider.get("class_provider_status") != "resolved"
            or not self._class_load_ready(host_definition)
        ):
            return False
        host_info = self._class_info(host_provider)
        if (
            not host_info
            or host_info.get("nest_host")
            or str(host_info.get("class_name") or "") != caller_host
        ):
            return False
        declared_members = set(host_info.get("nest_members") or ())
        return all(
            candidate == caller_host or candidate in declared_members
            for candidate in (caller_class, owner)
        )

    @staticmethod
    def _opcode_compatible(edge: Mapping[str, Any], member: Mapping[str, Any]) -> bool:
        opcode = int(edge["opcode"] or 0)
        is_static = bool(int(member["access_flags"]) & ACC_STATIC)
        if opcode in {178, 179, 184}:
            return is_static
        if opcode in {180, 181, 182, 183, 185}:
            return not is_static
        payload = _load_edge_json(edge["edge_json"] or "{}")
        tag = int(payload.get("tag") or (payload.get("bootstrap") or {}).get("tag") or 0)
        if tag == 6:
            return is_static
        if tag in {5, 7, 8, 9}:
            return not is_static
        return True

    def _type_resolution(self, edge: Mapping[str, Any], caller_realm: str) -> dict[str, Any]:
        owner = str(edge["symbolic_owner"] or "")
        provider_owner = _type_provider_owner(owner)
        provider = self._provider(caller_realm, provider_owner) if provider_owner else None
        definition = (
            self.definition_records.get((caller_realm, provider_owner))
            if provider_owner else None
        )
        if not provider_owner:
            status = "primitive_or_array_type"
        elif provider["class_provider_status"] != "resolved":
            status = "unresolved"
        elif not self._class_load_ready(definition):
            status = "class_definition_failed"
        else:
            status = "resolved"
        payload = {
            "direct_edge_identity": edge["direct_edge_identity"],
            "initiating_loader_realm_identity": caller_realm,
            "symbolic_owner": owner,
            "resolved_provider_owner": provider_owner,
            "symbolic_descriptor": edge["symbolic_descriptor"],
            "type_resolution_status": status,
            "provider_binding_identity": (provider or {}).get("provider_binding_identity", ""),
            "class_definition_resolution_identity": (definition or {}).get(
                "class_definition_resolution_identity", ""
            ),
            "type_use": _loads(edge["edge_json"] or "{}"),
        }
        payload["type_resolution_identity"] = _identity(
            "type_resolution_identity", payload
        )
        return payload

    def _default_interface_initializers(
        self, realm: str, owner: str, visited: set[tuple[str, str]]
    ) -> tuple[list[str], bool]:
        key = (realm, owner)
        if key in visited:
            return [], True
        visited.add(key)
        provider = self._provider(realm, owner)
        definition = self.definition_records.get(key)
        if (
            provider.get("class_provider_status") != "resolved"
            or not definition
            or not self._class_load_ready(definition)
        ):
            return [], False
        info = self._class_info(provider)
        if not info:
            return [], False
        targets: list[str] = []
        complete = True
        defining = info["defining_loader_realm_identity"]
        for parent in info["interfaces"]:
            nested, nested_complete = self._default_interface_initializers(
                defining, parent, visited
            )
            targets.extend(nested)
            complete = complete and nested_complete
        declares_default = any(
            member["member_kind"] == "method"
            and member["member_name"] not in {"<init>", "<clinit>"}
            and not (int(member["access_flags"]) & (ACC_ABSTRACT | ACC_STATIC | ACC_PRIVATE))
            for member in info["members"]
        )
        if declares_default:
            targets.extend(
                member["member_identity"] for member in info["members"]
                if member["member_kind"] == "method"
                and member["member_name"] == "<clinit>"
                and member["descriptor"] == "()V"
            )
        return targets, complete

    def _append_class_initialization_chain(
        self,
        realm: str,
        name: str,
        visited: set[tuple[str, str]],
        chain: list[str],
    ) -> bool:
        """Append JVMS initialization targets without a recursive closure.

        A nested self-recursive function formerly allocated a reference cycle
        for every ``new``/``getstatic``/``putstatic``/``invokestatic`` edge.
        Those cycles captured the complete reconciler and could keep millions
        of class/member index entries alive until a later cyclic-GC pass.
        """
        key = (realm, name)
        if key in visited:
            return True
        visited.add(key)
        provider = self._provider(realm, name)
        definition = self.definition_records.get(key)
        if (
            provider.get("class_provider_status") != "resolved"
            or not definition
            or not self._class_load_ready(definition)
        ):
            return False
        info = self._class_info(provider)
        if not info:
            return False
        defining = info["defining_loader_realm_identity"]
        complete = True
        if not (info["access_flags"] & ACC_INTERFACE) and info["super_name"]:
            super_complete = self._append_class_initialization_chain(
                defining, info["super_name"], visited, chain
            )
            complete = super_complete
        for interface in info["interfaces"]:
            interface_targets, interface_complete = (
                self._default_interface_initializers(
                    defining, interface, visited
                )
            )
            chain.extend(interface_targets)
            complete = complete and interface_complete
        chain.extend(
            member["member_identity"] for member in info["members"]
            if member["member_kind"] == "method"
            and member["member_name"] == "<clinit>"
            and member["descriptor"] == "()V"
        )
        return complete

    def _class_initialization_resolution(
        self, edge: Mapping[str, Any], caller_realm: str, caller_class: str
    ) -> dict[str, Any]:
        trigger = _loads(edge["edge_json"] or "{}")
        owner = str(edge["symbolic_owner"] or "")
        target_owner = owner
        target_realm = caller_realm
        if trigger.get("trigger_kind") in {"invokestatic", "getstatic", "putstatic"}:
            kind = "field" if trigger.get("trigger_kind") in {"getstatic", "putstatic"} else "method"
            member, member_provider = self._resolve_symbolic_member(
                caller_realm,
                owner,
                kind,
                str(trigger.get("trigger_member_name") or ""),
                str(trigger.get("trigger_member_descriptor") or ""),
            )
            if member and member_provider:
                target_owner = str(member["class_name"])
                target_realm = str(
                    member_provider["selected_defining_loader_realm_identity"]
                )
        chain: list[str] = []
        complete = True
        visited: set[tuple[str, str]] = set()

        already_initialized = caller_class == target_owner and caller_realm == target_realm
        if not already_initialized:
            complete = self._append_class_initialization_chain(
                target_realm, target_owner, visited, chain
            )
        status = (
            "not_applicable_already_initialized"
            if already_initialized
            else ("resolved" if complete else "partial")
        )
        payload = {
            "direct_edge_identity": edge["direct_edge_identity"],
            "initiating_loader_realm_identity": caller_realm,
            "trigger_owner": owner,
            "initialized_owner": target_owner,
            "initialized_loader_realm_identity": target_realm,
            "class_initialization_status": status,
            "initializer_target_identities": list(dict.fromkeys(chain)),
            "coverage_status": "complete" if complete else "partial",
            "trigger": trigger,
        }
        payload["class_initialization_resolution_identity"] = _identity(
            "class_initialization_resolution_identity", payload
        )
        return payload

    def _member_loading_constraints(
        self,
        caller_defining_loader_realm: str,
        declaration_loader_realm: str,
        descriptor_type_names: Iterable[str],
    ) -> tuple[str, list[dict[str, Any]]]:
        """Compare prospective JVMS descriptor providers for one member.

        Field/method/interface-method resolution imposes ``N^L1 = N^L2``
        for each descriptor class name, where L1 defines the actual declaring
        class and L2 defines the caller. The fact store has already parsed and
        deduplicated those names, so this hot path performs cache-only provider
        comparisons and no descriptor parsing or SQLite lookup.

        A provider mismatch is *not* by itself proof that the JVM has already
        violated the constraint. JVMS 5.3.4 permits the constraint to be
        recorded before either (or both) initiating loaders has loaded N; the
        incompatible definition can fail only later. The per-realm definition
        verifier also runs realms in separate JVMs, so it cannot prove the two
        initiating-load events. Consequently this static path reports a
        deferred conflict, reserving a definite violation for future evidence
        produced by a same-JVM topology probe.
        """
        constraints: list[dict[str, Any]] = []
        aggregate = "not_applicable"
        # The sole caller supplies the tuple returned by
        # _loading_constraint_type_owners_from_edge_json, which has already
        # proved sorted/unique non-empty names. Rebuilding a set and sorting it
        # for every direct edge duplicated that work millions of times.
        for class_name in descriptor_type_names:
            if caller_defining_loader_realm == declaration_loader_realm:
                item = {
                    "class_name": class_name,
                    "caller_defining_loader_realm_identity": (
                        caller_defining_loader_realm
                    ),
                    "declaration_defining_loader_realm_identity": (
                        declaration_loader_realm
                    ),
                    "caller_class_identity": (
                        f"{class_name}@{caller_defining_loader_realm}"
                    ),
                    "declaration_class_identity": (
                        f"{class_name}@{declaration_loader_realm}"
                    ),
                    "provider_equivalent": True,
                    "constraint_status": "satisfied",
                    "evidence_kind": "same_defining_loader",
                    "runtime_load_evidence_status": "not_required",
                }
            else:
                caller_provider = self._provider(
                    caller_defining_loader_realm, class_name
                )
                declaration_provider = self._provider(
                    declaration_loader_realm, class_name
                )
                caller_status = str(
                    caller_provider.get("class_provider_status") or "missing"
                )
                declaration_status = str(
                    declaration_provider.get("class_provider_status")
                    or "missing"
                )
                caller_defining = str(
                    caller_provider.get(
                        "selected_defining_loader_realm_identity"
                    ) or ""
                )
                declaration_defining = str(
                    declaration_provider.get(
                        "selected_defining_loader_realm_identity"
                    ) or ""
                )
                both_resolved = (
                    caller_status == "resolved"
                    and declaration_status == "resolved"
                )
                equivalent = bool(
                    both_resolved
                    and caller_defining
                    and caller_defining == declaration_defining
                )
                constraint_status = (
                    "satisfied"
                    if equivalent else (
                        "deferred_conflict" if both_resolved else "unresolved"
                    )
                )
                item = {
                    "class_name": class_name,
                    "caller_defining_loader_realm_identity": (
                        caller_defining_loader_realm
                    ),
                    "declaration_defining_loader_realm_identity": (
                        declaration_loader_realm
                    ),
                    "caller_provider_binding_identity": str(
                        caller_provider.get("provider_binding_identity") or ""
                    ),
                    "declaration_provider_binding_identity": str(
                        declaration_provider.get("provider_binding_identity")
                        or ""
                    ),
                    "caller_provider_status": caller_status,
                    "declaration_provider_status": declaration_status,
                    "caller_class_identity": (
                        f"{class_name}@{caller_defining}"
                        if caller_defining else ""
                    ),
                    "declaration_class_identity": (
                        f"{class_name}@{declaration_defining}"
                        if declaration_defining else ""
                    ),
                    "provider_equivalent": equivalent,
                    "constraint_status": constraint_status,
                    "evidence_kind": (
                        "prospective_selected_defining_loader_identity"
                    ),
                    "runtime_load_evidence_status": "unavailable",
                }
            constraints.append(item)
            if item["constraint_status"] == "deferred_conflict":
                aggregate = "deferred_conflict"
            elif (
                item["constraint_status"] == "unresolved"
                and aggregate != "deferred_conflict"
            ):
                aggregate = "unresolved"
            elif aggregate == "not_applicable":
                aggregate = "satisfied"
        return aggregate, constraints

    def _resolve_edges(
        self,
        universe: tuple[tuple[str, str], ...],
        accumulator: _ReconciliationAccumulator,
    ) -> None:
        active_caller_binding_by_variant: dict[str, tuple[str, str]] = {}
        for caller in self.classes:
            artifact = self.artifacts.get(
                caller["artifact_instance_identity"]
            )
            if artifact is None:
                continue
            artifact_loader_realm = artifact["loader_realm_identity"]
            provider = self._provider(
                artifact_loader_realm, caller["class_name"]
            )
            if (
                provider.get("class_provider_status") == "resolved"
                and provider.get("selected_class_variant_identity")
                == caller["class_variant_identity"]
            ):
                active_caller_binding_by_variant[
                    caller["class_variant_identity"]
                ] = (
                    caller["artifact_instance_identity"],
                    str(provider[
                        "selected_defining_loader_realm_identity"
                    ]),
                )
        member_by_identity = self.member_by_identity
        hierarchy_complete = (
            self.profile.complete
            and self.capability.closed_world_dispatch
            and self.profile.payload.get("runtime_class_closure_coverage_status") == "complete"
            and not self.coverage_gaps
        )
        edge_scan_order = self.DIRECT_EDGE_SCAN_ORDER
        if edge_scan_order not in {"rowid", "direct_edge_identity"}:
            raise RuntimeReconciliationError(
                "RUNTIME_DIRECT_EDGE_SCAN_ORDER_INVALID", edge_scan_order
            )
        # ``direct_edge_identity`` is a uniformly distributed SHA-256 value.
        # Ordering a multi-gigabyte rowid table by that secondary index makes
        # SQLite perform one effectively random table lookup per edge. The
        # insertion rowid is deterministic and lets SQLite stream the complete
        # table sequentially; every edge still produces the same resolution
        # records. Only their sequence, private chunk grouping and aggregate
        # result identity change; downstream conclusions index the records by
        # their unchanged subject/record identities.
        for raw_edge in self.store.connection.execute(
            f"""
            SELECT direct_edge_identity,caller_member_identity,
                   caller_artifact_instance_identity,instruction_index,
                   bytecode_offset,edge_kind,opcode,
                   symbolic_owner,symbolic_name,symbolic_descriptor,edge_json
            FROM direct_edges
            ORDER BY {edge_scan_order}
            """
        ):
            # sqlite3.Row already provides stable name-based access. Copying
            # eleven columns into a new dict for every direct edge allocated
            # millions of short-lived hash tables without changing a value.
            edge = raw_edge
            caller_artifact = edge["caller_artifact_instance_identity"]
            caller = member_by_identity.get(edge["caller_member_identity"])
            if caller is None:
                continue
            caller_binding = active_caller_binding_by_variant.get(
                caller["class_variant_identity"]
            )
            if caller_binding is None or caller_binding[0] != caller_artifact:
                # A shadowed physical caller variant is not D in any target
                # runtime constant pool and therefore imposes no constraints.
                continue
            caller_realm = caller_binding[1]
            if edge["edge_kind"] == "type":
                accumulator.add(
                    "type_resolution",
                    self._type_resolution(edge, caller_realm),
                )
                continue
            if edge["edge_kind"] == "class_init":
                accumulator.add(
                    "class_initialization_resolution",
                    self._class_initialization_resolution(
                        edge,
                        caller_realm,
                        str(caller.get("class_name") or ""),
                    ),
                )
                continue
            if edge["edge_kind"] == "ldc_constant_dynamic":
                linkage = {
                    "direct_edge_identity": edge["direct_edge_identity"],
                    "initiating_loader_realm_identity": caller_realm,
                    "linkage_kind": "constant_dynamic",
                    "linkage_status": "represented_by_bootstrap_handles",
                    "coverage_status": "complete",
                    "payload": _loads(edge["edge_json"] or "{}"),
                }
                linkage["linkage_resolution_identity"] = _identity(
                    "linkage_resolution_identity", linkage
                )
                accumulator.add("linkage_resolution", linkage)
                continue
            owner = edge["symbolic_owner"]
            edge_json = str(edge["edge_json"] or "{}")
            edge_payload = _load_edge_json(edge_json)
            descriptor_type_names = (
                _loading_constraint_type_owners_from_edge_json(edge_json)
            )
            # Ordinary MethodHandle edges store the handle directly, while an
            # invokedynamic bootstrap edge wraps it in ``payload.bootstrap``.
            # Preserve the JVMS reference kind in both shapes: tags 1..4 are
            # field references and therefore use a field descriptor/loading
            # constraint, even though the graph edge itself is not named
            # ``field``.
            bootstrap_payload = edge_payload.get("bootstrap") or {}
            handle_tag = int(
                edge_payload.get("tag")
                or (
                    bootstrap_payload.get("tag")
                    if isinstance(bootstrap_payload, Mapping) else 0
                )
                or 0
            )
            kind = (
                "field"
                if edge["edge_kind"] == "field" or handle_tag in {1, 2, 3, 4}
                else "method"
            )
            array_clone = (
                owner.startswith("[")
                and kind == "method"
                and edge["symbolic_name"] == "clone"
                and edge["symbolic_descriptor"] == "()Ljava/lang/Object;"
            )
            # Array classes have no classfile provider.  Their ``clone`` member
            # is a JVM-defined public operation whose declaration is rooted in
            # Object; resolving an object-array class still requires its
            # component class to be definition-ready.
            definition_owner = (
                (_type_provider_owner(owner) or "java/lang/Object")
                if array_clone else owner
            )
            provider = self._provider(caller_realm, definition_owner)
            definition = self.definition_records.get(
                (caller_realm, definition_owner)
            )
            payload = {
                "direct_edge_identity": edge["direct_edge_identity"],
                "initiating_loader_realm_identity": caller_realm,
                "symbolic_owner": owner,
                "symbolic_name": edge["symbolic_name"],
                "symbolic_descriptor": edge["symbolic_descriptor"],
                "provider_binding_identity": provider["provider_binding_identity"],
                "class_definition_resolution_identity": (
                    definition or {}
                ).get("class_definition_resolution_identity", ""),
            }
            if provider["class_provider_status"] != "resolved":
                status = "ambiguous" if provider["class_provider_status"] == "ambiguous" else "no_class_definition"
                linkage_status = status
            elif not self._class_load_ready(definition):
                status = "class_definition_failed"
                linkage_status = status
            else:
                resolution_owner = "java/lang/Object" if array_clone else owner
                member, member_provider = self._resolve_symbolic_member(
                    caller_realm,
                    resolution_owner,
                    kind,
                    edge["symbolic_name"],
                    edge["symbolic_descriptor"],
                )
                if member is None:
                    status = "no_such_member"
                    linkage_status = status
                else:
                    status = "resolved"
                    payload["resolved_member_identity"] = member["member_identity"]
                    payload["resolved_owner"] = member["class_name"]
                    payload["resolved_defining_loader_realm_identity"] = member_provider[
                        "selected_defining_loader_realm_identity"
                    ]
                    if array_clone:
                        payload["jvm_array_member_semantics"] = "public_clone"
                    if not array_clone and not self._member_accessible(
                        str(caller.get("class_name") or ""),
                        caller_realm,
                        member,
                        member_provider,
                    ):
                        linkage_status = "illegal_access"
                    else:
                        constraint_status, constraints = (
                            self._member_loading_constraints(
                                caller_realm,
                                str(member_provider[
                                    "selected_defining_loader_realm_identity"
                                ]),
                                descriptor_type_names,
                            )
                        )
                        payload["loading_constraint_status"] = (
                            constraint_status
                        )
                        payload["loading_constraints"] = constraints
                        if constraint_status == "deferred_conflict":
                            linkage_status = (
                                "loading_constraint_deferred_conflict"
                            )
                            payload["linkage_failure_reason"] = (
                                "prospective_descriptor_type_provider_mismatch"
                            )
                        elif constraint_status == "unresolved":
                            linkage_status = "loading_constraint_unresolved"
                            payload["linkage_failure_reason"] = (
                                "descriptor_type_provider_unresolved"
                            )
                        elif not self._opcode_compatible(edge, member):
                            linkage_status = "incompatible_class_change"
                        else:
                            linkage_status = "resolved"
            member_record = {
                **payload,
                "member_resolution_status": status,
            }
            resolution_identity = _member_resolution_identity_native(
                member_record
            )
            member_record["member_resolution_identity"] = resolution_identity
            accumulator.add("member_resolution", member_record)

            executable_dispatch = edge["edge_kind"] == "method" and kind == "method"
            dispatch_fixed_by_final_declaration = False
            dispatch_fixed_by_closed_world_single_target = False
            if (
                executable_dispatch
                and linkage_status in {
                    "loader_constraint_violation",
                    "loading_constraint_deferred_conflict",
                    "loading_constraint_unresolved",
                }
            ):
                dispatch_status = "unresolved"
                targets = ()
                coverage = "partial"
            elif not executable_dispatch or status != "resolved":
                dispatch_status = "not_applicable" if not executable_dispatch else "unresolved"
                targets = ()
                coverage = "complete" if dispatch_status == "not_applicable" else "partial"
            else:
                opcode = int(edge["opcode"] or 0)
                virtual = opcode in {182, 185} or handle_tag in {5, 9}
                if array_clone:
                    dispatch_fixed_by_final_declaration = True
                    dispatch_status = "exact"
                    targets = (payload["resolved_member_identity"],)
                    coverage = "complete"
                elif not virtual:
                    dispatch_status = "exact"
                    targets = (payload["resolved_member_identity"],)
                    coverage = "complete"
                else:
                    resolved_owner_info = self._class_info(member_provider)
                    dispatch_is_fixed = bool(
                        int(member.get("access_flags") or 0) & ACC_FINAL
                        or int((resolved_owner_info or {}).get("access_flags") or 0)
                        & ACC_FINAL
                    )
                    if dispatch_is_fixed:
                        dispatch_fixed_by_final_declaration = True
                        dispatch_status = "exact"
                        targets = (payload["resolved_member_identity"],)
                        coverage = "complete"
                    else:
                        targets = self._virtual_dispatch_targets(
                            universe,
                            owner,
                            edge["symbolic_name"],
                            edge["symbolic_descriptor"],
                        )
                        if not targets:
                            dispatch_status = (
                                "no_concrete_implementation" if hierarchy_complete else "unresolved"
                            )
                            coverage = "complete" if hierarchy_complete else "partial"
                        elif hierarchy_complete:
                            dispatch_status = "exact" if len(targets) == 1 else "possible"
                            dispatch_fixed_by_closed_world_single_target = len(targets) == 1
                            coverage = "complete"
                        else:
                            dispatch_status = "partial_possible_set"
                            coverage = "partial"
            dispatch_identity = _dispatch_resolution_identity_native(
                edge["direct_edge_identity"],
                dispatch_status,
                targets,
                coverage,
                {
                    "member_resolution_identity": resolution_identity,
                    "hierarchy_coverage_complete": hierarchy_complete,
                    "dispatch_fixed_by_final_declaration": (
                        dispatch_fixed_by_final_declaration
                    ),
                    "dispatch_fixed_by_closed_world_single_target": (
                        dispatch_fixed_by_closed_world_single_target
                    ),
                },
            )
            accumulator.add("dispatch_resolution", {
                "direct_edge_identity": edge["direct_edge_identity"],
                "dispatch_status": dispatch_status,
                "implementation_target_identities": list(targets),
                "dispatch_coverage_status": coverage,
                "dispatch_resolution_identity": dispatch_identity,
                "member_resolution_identity": resolution_identity,
            })
            linkage = {
                "direct_edge_identity": edge["direct_edge_identity"],
                "initiating_loader_realm_identity": caller_realm,
                "linkage_kind": kind,
                "linkage_status": linkage_status,
                "coverage_status": (
                    "partial"
                    if linkage_status in {
                        "ambiguous", "unresolved", "unsupported",
                        "loading_constraint_deferred_conflict",
                        "loading_constraint_unresolved",
                    }
                    else "complete"
                ),
                "member_resolution_identity": resolution_identity,
            }
            for field in (
                "loading_constraint_status", "loading_constraints",
                "linkage_failure_reason",
            ):
                if field in payload:
                    linkage[field] = payload[field]
            linkage["linkage_resolution_identity"] = _identity(
                "linkage_resolution_identity", linkage
            )
            accumulator.add("linkage_resolution", linkage)

    def reconcile(
        self,
        *,
        retain_record_kinds: Iterable[str] | None = (),
    ) -> RuntimeReconciliationResult:
        """Build and atomically persist the complete runtime truth set.

        Chunking still bounds Python residency, but one SQLite transaction
        avoids thousands of durable commit boundaries on large Windows/VM
        disks. Any exception rolls every reconciliation chunk back, so a
        caller can never observe a partially persisted runtime result.
        """
        owns_transaction = not self.store.connection.in_transaction
        if owns_transaction:
            self.store.connection.execute("BEGIN")
        try:
            result = self._reconcile(retain_record_kinds=retain_record_kinds)
            if owns_transaction:
                self.store.connection.commit()
            return result
        except BaseException:
            if owns_transaction and self.store.connection.in_transaction:
                self.store.connection.rollback()
            raise
        finally:
            # These caches contain only immutable derivations of fact-store
            # edge payloads. They are useful throughout one side's multi-
            # million-edge walk but must not overlap the independent Oracle's
            # own large indexes or survive a failed pipeline attempt.
            _loading_constraint_type_owners_from_edge_json.cache_clear()
            _load_small_edge_json.cache_clear()

    def _reconcile(
        self,
        *,
        retain_record_kinds: Iterable[str] | None = (),
    ) -> RuntimeReconciliationResult:
        # Persisted SQLite chunks are the complete authority.  Retaining every
        # family by default made a routine multi-million-edge reconciliation
        # keep a second Python object graph alive.  Callers that deliberately
        # need a bounded family must opt in by name.
        retained_kinds = {
            str(kind) for kind in (retain_record_kinds or ())
        }
        universe = self._universe()
        accumulator = _ReconciliationAccumulator(
            self.store,
            self.context_identity,
            retained_kinds,
        )
        # Provider evidence is complete once the runtime universe is closed.
        # Persist it before target-JVM definition evidence is created so both
        # full record families never occupy the heap together.
        for key in universe:
            record = self._provider(*key)
            accumulator.add("provider_binding", record)
        self._compact_persisted_runtime_records(retained_kinds)
        self._build_definitions(universe, accumulator)
        # Resolution before definition evidence is complete can legitimately
        # return a different answer. Clear any diagnostic/preflight calls at
        # the exact point definitions become immutable, then cache only the
        # stable root resolutions used by the complete edge walk.
        self._symbolic_member_root_cache.clear()
        self._symbolic_member_cache_hits = 0
        self._symbolic_member_cache_misses = 0
        try:
            self._resolve_edges(universe, accumulator)
        finally:
            # Downstream phases consume persisted evidence, not this lookup
            # cache. Release its bounded but potentially sizeable key set
            # before the independent Oracle constructs its own graph, also on
            # an interrupted or failed edge walk.
            self._symbolic_member_root_cache.clear()
        for record in self._resource_selections():
            accumulator.add("resource_selection", record)
        accumulator.flush()
        gaps = tuple(sorted(self.coverage_gaps))
        coverage = "complete" if not gaps else "partial"
        universe_identity = canonical_identity_streaming(
            "runtime_reconciliation_universe_identity",
            {
                "runtime_profile_identity": self.profile.identity,
                "analysis_context_identity": self.context_identity,
                "contexts": StreamingCanonicalSequence(lambda: iter(universe)),
                "capability_policy_identity": self.capability.identity,
            },
            schema_version="1",
        )
        result_payload = {
            "analysis_context_identity": self.context_identity,
            "runtime_profile_identity": self.profile.identity,
            "universe_identity": universe_identity,
            "provider_binding_identities": accumulator.canonical_subject_identities(
                "provider_binding"
            ),
            "class_definition_identities": accumulator.canonical_subject_identities(
                "class_definition"
            ),
            "member_resolution_identities": accumulator.canonical_subject_identities(
                "member_resolution"
            ),
            "dispatch_resolution_identities": accumulator.canonical_subject_identities(
                "dispatch_resolution"
            ),
            "type_resolution_identities": accumulator.canonical_subject_identities(
                "type_resolution"
            ),
            "class_initialization_resolution_identities": (
                accumulator.canonical_subject_identities(
                    "class_initialization_resolution"
                )
            ),
            "linkage_resolution_identities": accumulator.canonical_subject_identities(
                "linkage_resolution"
            ),
            "resource_selection_identities": accumulator.canonical_subject_identities(
                "resource_selection"
            ),
            "coverage_status": coverage,
            "coverage_gaps": list(gaps),
        }
        return RuntimeReconciliationResult(
            analysis_context_identity=self.context_identity,
            runtime_profile_identity=self.profile.identity,
            universe_identity=universe_identity,
            provider_bindings=tuple(accumulator.records["provider_binding"]),
            class_definitions=tuple(accumulator.records["class_definition"]),
            member_resolutions=tuple(accumulator.records["member_resolution"]),
            dispatch_resolutions=tuple(accumulator.records["dispatch_resolution"]),
            type_resolutions=tuple(accumulator.records["type_resolution"]),
            class_initialization_resolutions=tuple(
                accumulator.records["class_initialization_resolution"]
            ),
            linkage_resolutions=tuple(accumulator.records["linkage_resolution"]),
            resource_selections=tuple(accumulator.records["resource_selection"]),
            coverage_status=coverage,
            coverage_gaps=gaps,
            identity=canonical_identity_streaming(
                "runtime_reconciliation_result_identity",
                result_payload,
                schema_version="1",
            ),
        )


__all__ = [
    "RuntimeCapabilityPolicy",
    "RuntimeReconciliationError",
    "RuntimeReconciliationResult",
    "RuntimeReconciler",
    "hydrate_runtime_reconciliation",
]
