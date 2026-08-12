#!/usr/bin/env python3
"""Target-runtime provider, definition, member-resolution and dispatch view."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
import json
from typing import Any, Iterable, Mapping
import zlib

from binary_definition_verifier import (
    ClassDefinitionVerifierError,
    verifier_identity,
    verify_class_definitions,
)
from binary_fact_store import BinaryFactStore
from binary_first_contract import (
    BinaryFirstContractError,
    StreamingCanonicalSequence,
    canonical_identity,
    canonical_identity_streaming,
)
from binary_first_model import (
    ClassDefinitionResolution,
    DispatchResolution,
    MemberResolution,
    ProviderBinding,
    RuntimeProfile,
)
from binary_platform_image import JdkPlatformImage, PlatformClassFact


ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_INTERFACE = 0x0200
ACC_ABSTRACT = 0x0400


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


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


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
    policy_version: str = "binary-runtime-capability-v1"
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
    provider_bindings: tuple[dict[str, Any], ...]
    class_definitions: tuple[dict[str, Any], ...]
    member_resolutions: tuple[dict[str, Any], ...]
    dispatch_resolutions: tuple[dict[str, Any], ...]
    type_resolutions: tuple[dict[str, Any], ...]
    class_initialization_resolutions: tuple[dict[str, Any], ...]
    linkage_resolutions: tuple[dict[str, Any], ...]
    resource_selections: tuple[dict[str, Any], ...]
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
        pending.append({
            "analysis_context_identity": self.analysis_context_identity,
            "record_kind": kind,
            "status": record[status_key],
            "subject_identity": record[identity_key],
            "payload": record,
        })
        if len(pending) >= self.CHUNK_SIZE:
            self._flush_kind(kind)

    def _flush_kind(self, kind: str) -> None:
        pending = self.pending[kind]
        if not pending:
            return
        self.store.add_reconciliation_records(
            pending,
            collect_identities=False,
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
        self.artifacts = {
            row["artifact_instance_identity"]: row
            for row in store.rows(
                "artifact_instances",
                where="runtime_profile_identity=?",
                parameters=(runtime_profile.identity,),
            )
        }
        # Runtime selection needs only these seven scalar fields.  The generic
        # metadata reader also materializes physical labels and content/contract
        # digests for every class, retaining several unused Python strings per
        # row across the whole reconciliation phase.
        self.classes = [
            dict(row)
            for row in store.connection.execute(
                """
                SELECT class_variant_identity,artifact_instance_identity,
                       class_name,class_major,multi_release_version,
                       parse_status,failure_kind
                FROM classes
                """
            )
        ]
        self.class_by_variant = {row["class_variant_identity"]: row for row in self.classes}
        self.class_fact_headers: dict[str, dict[str, Any]] = {}
        for row in store.connection.execute(
            "SELECT class_variant_identity,fact_zlib FROM classes"
        ):
            fact = json.loads(zlib.decompress(row["fact_zlib"]).decode("utf-8"))
            self.class_fact_headers[row["class_variant_identity"]] = {
                "class_name": fact.get("class_name"),
                "class_access": fact.get("class_access"),
                "super_name": fact.get("super_name"),
                "interfaces": tuple(fact.get("interfaces") or ()),
            }
        self.members_by_variant: dict[str, list[dict[str, Any]]] = {}
        self.member_by_identity: dict[str, dict[str, Any]] = {}
        for raw in store.connection.execute(
            """
            SELECT member_identity,class_variant_identity,class_name,
                   member_kind,member_name,descriptor,access_flags
            FROM members
            """
        ):
            row = dict(raw)
            self.members_by_variant.setdefault(row["class_variant_identity"], []).append(row)
            self.member_by_identity[row["member_identity"]] = row
        self.realms, self.entrypoint_realms, topology_gaps = self._loader_topology(payload)
        self.coverage_gaps = set(topology_gaps)
        profile_coverage = dict(payload.get("field_coverage") or {})
        for field_name in RuntimeProfile.REQUIRED_FIELDS:
            if profile_coverage.get(field_name) == "unknown":
                self.coverage_gaps.add(f"runtime_profile_field_unknown:{field_name}")
        if payload.get("resource_selection_coverage_status") != "complete":
            self.coverage_gaps.add("resource_selection_scope_incomplete")
        self.provider_bindings: dict[tuple[str, str], dict[str, Any]] = {}
        self.definition_records: dict[tuple[str, str], dict[str, Any]] = {}
        self.class_info_cache: dict[tuple[str, str], dict[str, Any] | None] = {}
        self.ancestor_type_cache: dict[tuple[str, str], frozenset[str]] = {}
        self.virtual_dispatch_cache: dict[
            tuple[str, str, str], tuple[str, ...]
        ] = {}
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
                    or (mr_enabled and row["multi_release_version"] <= self.target_java_major)
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
        binding = ProviderBinding(payload)
        payload["provider_binding_identity"] = binding.identity
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
        initial_classes.update(
            name for name in self.additional_initial_classes if name != "module-info"
        )
        # ``_provider`` may ask the platform image about every symbolic owner.
        # Resolve the whole initial frontier as one framed ASM batch instead of
        # launching a helper process once per previously unseen JDK class.
        self.platform.ensure_classes(initial_classes)
        contexts = set()
        pending = [(realm, name) for realm in self.entrypoint_realms for name in initial_classes]
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
        fact = self.class_fact_headers.get(str(variant or ""))
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

    def _build_definitions(self, universe: Iterable[tuple[str, str]]) -> None:
        selected_by_realm: dict[str, dict[str, str]] = {}
        for realm, name in universe:
            provider = self._provider(realm, name)
            if provider["class_provider_status"] != "resolved":
                continue
            variant = provider["selected_class_variant_identity"]
            row = self.class_by_variant.get(variant)
            if row and row["parse_status"] == "parsed":
                selected_by_realm.setdefault(
                    provider["selected_defining_loader_realm_identity"], {}
                )[name] = str(variant)
        verified: dict[tuple[str, str], dict[str, Any]] = {}
        for realm, selected in selected_by_realm.items():
            realm_config = self.realms.get(realm, {})
            parent = str(realm_config.get("parent") or self._platform_realm())
            supported_flat = (
                realm_config.get("delegation", "parent_first") == "parent_first"
                and parent == self._platform_realm()
                and realm_config.get("module_mode", "unnamed") == "unnamed"
            )
            if not supported_flat:
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
            for name, outcome in outcomes.items():
                verified[(realm, name)] = outcome

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
                elif self._artifact_security_unsupported(row["artifact_instance_identity"]):
                    definition_status = "security_failed"
                    evidence["reason"] = "signed_or_sealed_artifact_unsupported"
                elif not transformers_supported:
                    definition_status = "unsupported"
                    evidence["reason"] = "transformer_profile_unsupported"
                else:
                    defining_realm = provider["selected_defining_loader_realm_identity"]
                    outcome = verified.get((defining_realm, name))
                    if outcome is None:
                        definition_status = "unsupported"
                        evidence["reason"] = "target_jvm_verification_unavailable"
                    else:
                        definition_status = (
                            "definition_ready" if outcome["status"] == "definition_ready"
                            else self._definition_status_from_failure(outcome.get("failure_kind", ""))
                        )
                        evidence["target_jvm_verification"] = outcome
            resolution = ClassDefinitionResolution(
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
                "class_definition_resolution_identity": resolution.identity,
                "provider_binding_identity": provider["provider_binding_identity"],
                "evidence": evidence,
            }
            self.definition_records[(realm, name)] = record

    def _artifact_security_unsupported(self, artifact_identity: str) -> bool:
        cached = self.artifact_security_unsupported_cache.get(artifact_identity)
        if cached is not None:
            return cached
        resources = self.store.rows(
            "resources",
            where="artifact_instance_identity=? AND resource_category='operational_security'",
            parameters=(artifact_identity,),
        )
        if resources and not self.capability.signed_artifacts_supported:
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
            "module_name": module_name,
            "members": members,
        }
        self.class_info_cache[cache_key] = result
        return result

    def _resolve_symbolic_member(
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
        if kind == "field":
            parents = [*info["interfaces"], info["super_name"]]
        elif name == "<init>":
            parents = []
        else:
            parents = [info["super_name"], *info["interfaces"]]
        defining = info["defining_loader_realm_identity"]
        for parent in parents:
            if not parent:
                continue
            resolved, resolved_provider = self._resolve_symbolic_member(
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
            return caller_class == owner and caller_realm == defining
        same_runtime_package = caller_realm == defining and _package(caller_class) == _package(owner)
        if flags & ACC_PROTECTED:
            return same_runtime_package or self._is_subtype(caller_realm, caller_class, owner)
        return same_runtime_package

    @staticmethod
    def _opcode_compatible(edge: Mapping[str, Any], member: Mapping[str, Any]) -> bool:
        opcode = int(edge.get("opcode") or 0)
        is_static = bool(int(member["access_flags"]) & ACC_STATIC)
        if opcode in {178, 179, 184}:
            return is_static
        if opcode in {180, 181, 182, 183, 185}:
            return not is_static
        payload = _loads(edge.get("edge_json") or "{}")
        tag = int(payload.get("tag") or (payload.get("bootstrap") or {}).get("tag") or 0)
        if tag == 6:
            return is_static
        if tag in {5, 7, 8, 9}:
            return not is_static
        return True

    def _type_resolution(self, edge: Mapping[str, Any], caller_realm: str) -> dict[str, Any]:
        owner = str(edge.get("symbolic_owner") or "")
        provider_owner = _type_provider_owner(owner)
        provider = self._provider(caller_realm, provider_owner) if provider_owner else None
        definition = (
            self.definition_records.get((caller_realm, provider_owner))
            if provider_owner else None
        )
        if not provider_owner:
            status = "primitive_or_array_type"
        elif not provider or provider["class_provider_status"] != "resolved":
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
            "symbolic_descriptor": edge.get("symbolic_descriptor"),
            "type_resolution_status": status,
            "provider_binding_identity": (provider or {}).get("provider_binding_identity", ""),
            "class_definition_resolution_identity": (definition or {}).get(
                "class_definition_resolution_identity", ""
            ),
            "type_use": _loads(edge.get("edge_json") or "{}"),
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

    def _class_initialization_resolution(
        self, edge: Mapping[str, Any], caller_realm: str, caller_class: str
    ) -> dict[str, Any]:
        trigger = _loads(edge.get("edge_json") or "{}")
        owner = str(edge.get("symbolic_owner") or "")
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

        def visit(realm: str, name: str) -> None:
            nonlocal complete
            key = (realm, name)
            if key in visited:
                return
            visited.add(key)
            provider = self._provider(realm, name)
            definition = self.definition_records.get(key)
            if (
                provider.get("class_provider_status") != "resolved"
                or not definition
                or not self._class_load_ready(definition)
            ):
                complete = False
                return
            info = self._class_info(provider)
            if not info:
                complete = False
                return
            defining = info["defining_loader_realm_identity"]
            if not (info["access_flags"] & ACC_INTERFACE) and info["super_name"]:
                visit(defining, info["super_name"])
            for interface in info["interfaces"]:
                interface_targets, interface_complete = self._default_interface_initializers(
                    defining, interface, visited
                )
                chain.extend(interface_targets)
                complete = complete and interface_complete
            chain.extend(
                member["member_identity"] for member in info["members"]
                if member["member_kind"] == "method"
                and member["member_name"] == "<clinit>"
                and member["descriptor"] == "()V"
            )

        already_initialized = caller_class == target_owner and caller_realm == target_realm
        if not already_initialized:
            visit(target_realm, target_owner)
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

    def _resolve_edges(
        self,
        universe: tuple[tuple[str, str], ...],
        accumulator: _ReconciliationAccumulator,
    ) -> None:
        artifact_realm = {
            identity: row["loader_realm_identity"] for identity, row in self.artifacts.items()
        }
        member_by_identity = self.member_by_identity
        hierarchy_complete = (
            self.profile.complete
            and self.capability.closed_world_dispatch
            and self.profile.payload.get("runtime_class_closure_coverage_status") == "complete"
            and not self.coverage_gaps
        )
        for raw_edge in self.store.connection.execute(
            """
            SELECT direct_edge_identity,caller_member_identity,
                   caller_artifact_instance_identity,edge_kind,opcode,
                   symbolic_owner,symbolic_name,symbolic_descriptor,edge_json
            FROM direct_edges
            ORDER BY direct_edge_identity
            """
        ):
            edge = dict(raw_edge)
            caller_artifact = edge["caller_artifact_instance_identity"]
            if caller_artifact not in artifact_realm:
                continue
            caller = member_by_identity.get(edge["caller_member_identity"])
            caller_realm = artifact_realm[caller_artifact]
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
                        str((caller or {}).get("class_name") or ""),
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
                    "payload": _loads(edge.get("edge_json") or "{}"),
                }
                linkage["linkage_resolution_identity"] = _identity(
                    "linkage_resolution_identity", linkage
                )
                accumulator.add("linkage_resolution", linkage)
                continue
            owner = edge["symbolic_owner"]
            edge_payload = _loads(edge.get("edge_json") or "{}")
            handle_tag = int(edge_payload.get("tag") or 0)
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
                    if not self._opcode_compatible(edge, member):
                        linkage_status = "incompatible_class_change"
                    elif not array_clone and not self._member_accessible(
                        str((caller or {}).get("class_name") or ""),
                        caller_realm,
                        member,
                        member_provider,
                    ):
                        linkage_status = "illegal_access"
                    else:
                        linkage_status = "resolved"
            resolution = MemberResolution({"member_resolution_status": status, **payload})
            member_record = {
                **payload,
                "member_resolution_status": status,
                "member_resolution_identity": resolution.identity,
            }
            accumulator.add("member_resolution", member_record)

            executable_dispatch = edge["edge_kind"] == "method" and kind == "method"
            dispatch_fixed_by_final_declaration = False
            dispatch_fixed_by_closed_world_single_target = False
            if not executable_dispatch or status != "resolved":
                dispatch_status = "not_applicable" if not executable_dispatch else "unresolved"
                targets = ()
                coverage = "complete" if dispatch_status == "not_applicable" else "partial"
            else:
                opcode = int(edge.get("opcode") or 0)
                handle_tag = int(edge_payload.get("tag") or 0)
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
            dispatch = DispatchResolution(
                edge["direct_edge_identity"],
                dispatch_status,
                targets,
                coverage,
                {
                    "member_resolution_identity": resolution.identity,
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
                "dispatch_resolution_identity": dispatch.identity,
                "member_resolution_identity": resolution.identity,
            })
            linkage = {
                "direct_edge_identity": edge["direct_edge_identity"],
                "initiating_loader_realm_identity": caller_realm,
                "linkage_kind": kind,
                "linkage_status": linkage_status,
                "coverage_status": (
                    "partial"
                    if linkage_status in {"ambiguous", "unresolved", "unsupported"}
                    else "complete"
                ),
                "member_resolution_identity": resolution.identity,
            }
            linkage["linkage_resolution_identity"] = _identity(
                "linkage_resolution_identity", linkage
            )
            accumulator.add("linkage_resolution", linkage)

    def reconcile(
        self,
        *,
        retain_record_kinds: Iterable[str] | None = None,
    ) -> RuntimeReconciliationResult:
        retained_kinds = (
            set(_RECONCILIATION_RECORD_FIELDS)
            if retain_record_kinds is None
            else {str(kind) for kind in retain_record_kinds}
        )
        universe = self._universe()
        self._build_definitions(universe)
        providers = []
        for key in universe:
            record = self._provider(*key)
            providers.append(record)
        definitions = [self.definition_records[key] for key in universe]
        accumulator = _ReconciliationAccumulator(
            self.store,
            self.context_identity,
            retained_kinds,
        )
        for record in providers:
            accumulator.add("provider_binding", record)
        for record in definitions:
            accumulator.add("class_definition", record)
        # The accumulator now owns retained provider/definition references.
        # Drop the duplicate list containers before resolving the much larger
        # edge fact sets.
        providers = accumulator.records["provider_binding"]
        definitions = accumulator.records["class_definition"]
        self._resolve_edges(universe, accumulator)
        for record in self._resource_selections():
            accumulator.add("resource_selection", record)
        accumulator.flush()
        gaps = tuple(sorted(self.coverage_gaps))
        coverage = "complete" if not gaps else "partial"
        universe_identity = _identity(
            "runtime_reconciliation_universe_identity",
            {
                "runtime_profile_identity": self.profile.identity,
                "analysis_context_identity": self.context_identity,
                "contexts": [list(item) for item in universe],
                "capability_policy_identity": self.capability.identity,
            },
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
]
