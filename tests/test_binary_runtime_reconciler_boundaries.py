import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_binary_runtime_reconciler as existing


rr = existing.runtime_reconciler
RuntimeReconciler = existing.RuntimeReconciler
BinaryFactStore = existing.BinaryFactStore


def resolved_provider(
    name="demo/Api",
    *,
    realm="app",
    variant="variant",
    artifact="artifact",
    identity="provider",
):
    return {
        "runtime_profile_identity": "profile",
        "initiating_loader_realm_identity": realm,
        "class_name": name,
        "class_provider_status": "resolved",
        "provider_binding_identity": identity,
        "selected_defining_loader_realm_identity": realm,
        "selected_artifact_instance_identity": artifact,
        "selected_class_variant_identity": variant,
        "provider_equivalence_set_identity": "equivalence",
    }


def definition(
    status="definition_ready", *, load_status="ready", identity="definition",
    evidence=None,
):
    return {
        "class_definition_status": status,
        "class_load_status": load_status,
        "class_definition_resolution_identity": identity,
        "evidence": evidence or {},
    }


class CaptureAccumulator:
    def __init__(self, retained_kinds=()):
        self.retained_kinds = frozenset(retained_kinds)
        self.items = []

    def add(self, kind, record):
        self.items.append((kind, record))


class FakePlatform:
    identity = "platform-id"
    java_major = 17

    def __init__(self, classes=None, exports=None):
        self.classes = classes or {}
        self.exports = exports or {}
        self.ensured = []

    def get_class(self, name):
        return self.classes.get(name)

    def ensure_classes(self, names):
        self.ensured.append(set(names))

    def module_exports(self):
        return self.exports


def platform_fact(name="java/lang/Object", *, module="java.base", variant="platform-v"):
    return SimpleNamespace(
        module_name=module,
        class_variant_identity=variant,
        fact={
            "class_name": name,
            "class_access": rr.ACC_PUBLIC,
            "super_name": None,
            "interfaces": [],
            "fields": [],
            "methods": [],
        },
    )


def blank_reconciler():
    reconciler = RuntimeReconciler.__new__(RuntimeReconciler)
    reconciler.profile = SimpleNamespace(
        identity="profile",
        complete=True,
        payload={
            "runtime_class_closure_coverage_status": "complete",
            "runtime_security_and_package_sealing_policy_identity": (
                "standard-unsealed-unsigned-v1"
            ),
            "agent_transformer_plugin_profile_identities": [],
        },
    )
    reconciler.platform = FakePlatform()
    reconciler.capability = rr.RuntimeCapabilityPolicy()
    reconciler.context_identity = "context"
    reconciler.target_java_major = 17
    reconciler.target_class_major = 61
    reconciler.artifacts = {}
    reconciler.classes = []
    reconciler.class_by_variant = {}
    reconciler.members_by_variant = {}
    reconciler.member_by_identity = {}
    reconciler.realms = {
        "platform": {
            "identity": "platform", "kind": "platform",
            "delegation": "parent_first", "module_mode": "named-platform",
        },
        "app": {
            "identity": "app", "kind": "application", "parent": "platform",
            "delegation": "parent_first", "module_mode": "unnamed",
        },
    }
    reconciler.entrypoint_realms = ("app",)
    reconciler.coverage_gaps = set()
    reconciler.provider_bindings = {}
    reconciler.definition_records = {}
    reconciler.class_info_cache = {}
    reconciler.ancestor_type_cache = {}
    reconciler.virtual_dispatch_cache = {}
    reconciler._symbolic_member_root_cache = {}
    reconciler._symbolic_member_cache_hits = 0
    reconciler._symbolic_member_cache_misses = 0
    reconciler.artifact_manifest_cache = {}
    reconciler.artifact_security_unsupported_cache = {}
    reconciler.concrete_subtype_cache = {}
    reconciler.concrete_subtype_index_built = False
    reconciler.resource_categories_by_name = {}
    reconciler.resource_candidates_by_realm_name = {}
    return reconciler


class RuntimeReconcilerBoundaryTest(unittest.TestCase):
    def test_compact_rows_json_and_type_owner_boundaries(self):
        with self.assertRaises(rr.RuntimeReconciliationError) as raised:
            rr._ClassRow(())
        self.assertEqual(
            raised.exception.reason_code, "RUNTIME_COMPACT_ROW_SHAPE_INVALID",
        )
        values = tuple(range(len(rr._ClassRow.FIELDS)))
        row = rr._ClassRow(values)
        self.assertEqual(row["class_name"], 2)
        self.assertEqual(len(row), len(values))
        self.assertEqual(set(row), set(rr._ClassRow.FIELDS))
        self.assertEqual((row | {"class_name": "override"})["class_name"], "override")
        self.assertEqual(({"prefix": True} | row)["prefix"], True)
        with self.assertRaises(KeyError):
            _ = row["missing"]
        missing_values = list(values)
        missing_values[2] = rr._MISSING_COMPACT_VALUE
        missing_row = rr._ClassRow(missing_values)
        with self.assertRaises(KeyError):
            _ = missing_row["class_name"]
        self.assertNotIn("class_name", missing_row)
        all_missing = rr._ClassRow(
            [rr._MISSING_COMPACT_VALUE] * len(rr._ClassRow.FIELDS)
        )
        self.assertEqual(tuple(all_missing), ())

        pool = {}
        marker = object()
        self.assertIs(rr._shared_string(marker, pool), marker)
        first = rr._shared_string("same", pool)
        self.assertIs(first, rr._shared_string("same", pool))
        self.assertEqual(rr._shared_string_tuple_json("[]", pool), ())
        self.assertEqual(
            rr._shared_string_tuple_json('["same","other"]', pool),
            ("same", "other"),
        )

        self.assertEqual(rr._type_provider_owner("demo/Api"), "demo/Api")
        self.assertEqual(rr._type_provider_owner("[[Ldemo/Api;"), "demo/Api")
        self.assertEqual(rr._type_provider_owner("[Ldemo/Broken"), "")
        self.assertEqual(rr._type_provider_owner("[I"), "")
        self.assertEqual(rr._type_provider_owner(""), "")
        self.assertEqual(rr._loads(""), {})
        self.assertEqual(rr._loads('{"a":1}'), {"a": 1})
        self.assertEqual(rr._load_edge_json(""), {})

    def test_class_load_readiness_all_evidence_paths(self):
        self.assertFalse(rr.class_load_is_ready(None))
        self.assertTrue(rr.class_load_is_ready({"class_load_status": "ready"}))
        self.assertTrue(rr.class_load_is_ready({
            "class_definition_status": "definition_ready",
        }))
        self.assertTrue(rr.class_load_is_ready({
            "evidence": {"target_jvm_verification": {
                "failure_phase": "member_linkage",
            }},
        }))
        self.assertFalse(rr.class_load_is_ready({"evidence": {}}))
        self.assertFalse(rr.class_load_is_ready({
            "evidence": {"target_jvm_verification": None},
        }))

    def test_hydration_unknown_existing_missing_and_legacy(self):
        legacy = SimpleNamespace(provider_bindings=())
        self.assertIs(
            rr.hydrate_runtime_reconciliation(None, legacy, ("provider_binding",)),
            legacy,
        )
        base = rr.RuntimeReconciliationResult(
            "context", "profile", "universe",
            ({"provider": 1},), (), (), (), (), (), (), (),
            "complete", (), "identity",
        )
        with self.assertRaises(rr.RuntimeReconciliationError) as raised:
            rr.hydrate_runtime_reconciliation(
                SimpleNamespace(), base, ("unknown",),
            )
        self.assertEqual(
            raised.exception.reason_code,
            "RUNTIME_RECONCILIATION_HYDRATION_KIND_INVALID",
        )

        store = SimpleNamespace(
            reconciliation_payloads=lambda kind: ({"kind": kind},),
        )
        unchanged = rr.hydrate_runtime_reconciliation(
            store, base, ("provider_binding",),
        )
        self.assertIs(unchanged, base)
        hydrated = rr.hydrate_runtime_reconciliation(
            store, base, ("member_resolution", "provider_binding"),
        )
        self.assertEqual(
            hydrated.member_resolutions, ({"kind": "member_resolution"},),
        )

    def test_compact_identity_sequence_and_accumulator_contracts(self):
        sequence = rr._CompactIdentitySequence()
        for invalid in ("", "not-hex", "00", "AA" * 32):
            with self.subTest(invalid=invalid), self.assertRaises(
                rr.RuntimeReconciliationError
            ) as raised:
                sequence.append(invalid)
            self.assertEqual(
                raised.exception.reason_code,
                "RUNTIME_RECONCILIATION_SUBJECT_IDENTITY_INVALID",
            )
        digest = "ab" * 32
        sequence.append(digest)
        self.assertEqual(tuple(sequence._iter_identities()), (digest,))
        self.assertEqual(list(sequence.canonical_sequence()), [digest])

        with self.assertRaises(rr.RuntimeReconciliationError) as raised:
            rr._ReconciliationAccumulator(
                SimpleNamespace(), "context", ("unknown",),
            )
        self.assertEqual(
            raised.exception.reason_code,
            "RUNTIME_RECONCILIATION_RETAINED_KIND_INVALID",
        )

        writes = []
        store = SimpleNamespace(
            add_reconciliation_payloads=lambda **kwargs: writes.append(kwargs),
        )
        accumulator = rr._ReconciliationAccumulator(
            store, "context", ("provider_binding",),
        )
        accumulator._flush_kind("provider_binding")
        record = {
            "class_provider_status": "resolved",
            "provider_binding_identity": digest,
        }
        accumulator.add("provider_binding", record)
        self.assertEqual(accumulator.records["provider_binding"], [record])
        self.assertIsInstance(
            accumulator.canonical_subject_identities("provider_binding"), list,
        )
        accumulator.flush()
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["record_kind"], "provider_binding")

        compact = rr._ReconciliationAccumulator(store, "context", ())
        compact.add("provider_binding", record)
        self.assertEqual(compact.records["provider_binding"], [])
        self.assertIsInstance(
            compact.canonical_subject_identities("provider_binding"),
            rr.StreamingCanonicalSequence,
        )
        with patch.object(rr._ReconciliationAccumulator, "CHUNK_SIZE", 1):
            immediate = rr._ReconciliationAccumulator(store, "context", ())
            immediate.add("provider_binding", record)
            self.assertEqual(immediate.pending["provider_binding"], [])

    def test_loader_topology_modern_legacy_gaps_and_cycle(self):
        reconciler = blank_reconciler()
        reconciler.artifacts = {
            "a": {"loader_realm_identity": "app"},
            "b": {"loader_realm_identity": "undeclared"},
        }
        modern = {
            "loader_topology": {
                "coverage_status": "partial",
                "entrypoint_realms": [],
                "realms": [
                    None,
                    {},
                    {
                        "identity": "platform", "kind": "platform",
                        "delegation": "unsupported",
                        "module_mode": "unsupported-platform-mode",
                    },
                    {
                        "identity": "app", "kind": "application",
                        "parent": "platform", "delegation": "unsupported",
                        "module_mode": "named",
                    },
                ],
            },
        }
        realms, entrypoints, gaps = reconciler._loader_topology(modern)
        self.assertEqual(set(realms), {"platform", "app"})
        self.assertEqual(entrypoints, ("app", "undeclared"))
        self.assertIn("loader_topology_invalid_realm", gaps)
        self.assertIn("loader_topology_coverage_incomplete", gaps)
        self.assertIn("loader_realm_undeclared:undeclared", gaps)
        self.assertIn("loader_delegation_unsupported:app", gaps)
        self.assertIn("module_mode_unsupported:app", gaps)
        self.assertNotIn("module_mode_unsupported:platform", gaps)

        legacy_realms, legacy_entrypoints, legacy_gaps = (
            reconciler._loader_topology({
                "loader_topology": {
                    "application": {"entrypoint": True},
                    "worker": {"entrypoint": False},
                    "ignored": "not-a-mapping",
                },
            })
        )
        self.assertEqual(set(legacy_realms), {"application", "worker"})
        self.assertEqual(legacy_entrypoints, ("application",))
        self.assertTrue(legacy_gaps)

        reconciler.artifacts = {}
        realms, entrypoints, gaps = reconciler._loader_topology({})
        self.assertEqual(realms, {})
        self.assertEqual(entrypoints, ())
        self.assertIn("loader_topology_missing", gaps)

        with self.assertRaises(rr.RuntimeReconciliationError) as raised:
            reconciler._loader_topology({
                "loader_topology": {
                    "realms": [
                        {"identity": "a", "parent": "b"},
                        {"identity": "b", "parent": "a"},
                    ],
                },
            })
        self.assertEqual(raised.exception.reason_code, "LOADER_TOPOLOGY_CYCLE")
        realms, _entrypoints, _gaps = reconciler._loader_topology({
            "loader_topology": {
                "realms": "legacy-value",
                "app": {"parent": "outside", "entrypoint": True},
            },
        })
        self.assertIn("app", realms)
        realms, entrypoints, gaps = reconciler._loader_topology({
            "loader_topology": "not-a-mapping",
        })
        self.assertEqual((realms, entrypoints), ({}, ()))
        self.assertIn("loader_topology_missing", gaps)

    def test_artifact_manifest_empty_pairs_values_and_cache(self):
        reconciler = blank_reconciler()
        calls = []

        def rows(_table, *, parameters, **_kwargs):
            artifact = parameters[0]
            calls.append(artifact)
            return {
                "empty": [],
                "empty-pairs": [{"resource_semantic_json": "[]"}],
                "values": [{
                    "resource_semantic_json": json.dumps([
                        ["Multi-Release", "true"],
                        ["Multi-Release", "false"],
                        ["Sealed", "true"],
                    ]),
                }],
            }[artifact]

        reconciler.store = SimpleNamespace(rows=rows)
        self.assertEqual(reconciler._artifact_manifest("empty"), {})
        self.assertEqual(reconciler._artifact_manifest("empty-pairs"), {})
        self.assertEqual(reconciler._artifact_manifest("values"), {
            "multi-release": ["true", "false"],
            "sealed": ["true"],
        })
        self.assertEqual(reconciler._artifact_manifest("values"), {
            "multi-release": ["true", "false"],
            "sealed": ["true"],
        })
        self.assertEqual(calls.count("values"), 1)

    def test_effective_candidates_multi_release_and_ambiguity(self):
        reconciler = blank_reconciler()
        reconciler.artifacts = {
            "a": {
                "loader_realm_identity": "app",
                "runtime_classpath_index": 1,
                "container_loader_policy_version": "unsupported",
            },
            "b": {
                "loader_realm_identity": "app",
                "runtime_classpath_index": 0,
                "container_loader_policy_version": "flat-parent-first-v1",
            },
        }
        reconciler.classes = [
            {"artifact_instance_identity": "outside", "class_name": "Outside", "multi_release_version": 0},
            {"artifact_instance_identity": "a", "class_name": "module-info", "multi_release_version": 0},
            {"artifact_instance_identity": "a", "class_name": "Base", "multi_release_version": 0, "class_variant_identity": "base"},
            {"artifact_instance_identity": "a", "class_name": "Layered", "multi_release_version": 0, "class_variant_identity": "layered-base"},
            {"artifact_instance_identity": "a", "class_name": "Layered", "multi_release_version": 11, "class_variant_identity": "layered-v11"},
            {"artifact_instance_identity": "a", "class_name": "PreNine", "multi_release_version": 7, "class_variant_identity": "pre-nine"},
            {"artifact_instance_identity": "a", "class_name": "Versioned", "multi_release_version": 11, "class_variant_identity": "v11-a"},
            {"artifact_instance_identity": "a", "class_name": "Future", "multi_release_version": 99, "class_variant_identity": "future"},
            {"artifact_instance_identity": "a", "class_name": "Duplicate", "multi_release_version": 0, "class_variant_identity": "dup-1"},
            {"artifact_instance_identity": "a", "class_name": "Duplicate", "multi_release_version": 0, "class_variant_identity": "dup-2"},
            {"artifact_instance_identity": "b", "class_name": "Base", "multi_release_version": 0, "class_variant_identity": "base-b"},
        ]
        manifests = {
            "a": {"multi-release": ["TRUE", "true"]},
            "b": {"multi-release": ["true"]},
        }
        reconciler._artifact_manifest = lambda identity: manifests[identity]
        candidates = reconciler._effective_class_candidates()
        self.assertIn("manifest_multi_release_ambiguous:a", reconciler.coverage_gaps)
        self.assertIn("container_loader_policy_unsupported:a", reconciler.coverage_gaps)
        self.assertIn("class_variant_ambiguous:a:Duplicate:0", reconciler.coverage_gaps)
        self.assertNotIn("Versioned", candidates.get("app", {}))
        self.assertNotIn("Future", candidates.get("app", {}))
        self.assertEqual(
            [row["artifact_instance_identity"] for row in candidates["app"]["Base"]],
            ["b", "a"],
        )

        reconciler.coverage_gaps.clear()
        manifests["a"] = {"multi-release": ["true"]}
        candidates = reconciler._effective_class_candidates()
        self.assertEqual(
            candidates["app"]["Versioned"][0]["class_variant_identity"],
            "v11-a",
        )
        self.assertEqual(
            candidates["app"]["Layered"][0]["class_variant_identity"],
            "layered-v11",
        )
        self.assertNotIn("PreNine", candidates["app"])

    def test_resource_selection_parent_child_cycle_and_records(self):
        reconciler = blank_reconciler()
        reconciler.realms["child"] = {
            "identity": "child", "kind": "application", "parent": "app",
            "delegation": "child_first",
        }
        parent_row = {"artifact_instance_identity": "parent", "physical_entry_identity": "p"}
        child_row = {"artifact_instance_identity": "child", "physical_entry_identity": "c"}
        reconciler.resource_candidates_by_realm_name = {
            ("app", "service"): [parent_row],
            ("child", "service"): [child_row],
        }
        self.assertEqual(
            reconciler._resource_mechanism("META-INF/services/x", "unknown"),
            "ordered_all",
        )
        self.assertEqual(
            reconciler._resource_mechanism("x", "runtime_topology"),
            "ordered_all",
        )
        self.assertEqual(
            reconciler._resource_mechanism("x", "unknown"),
            "classloader_first",
        )
        with self.assertRaises(rr.RuntimeReconciliationError) as raised:
            reconciler._selected_resources(
                "child", "service", "ordered_all",
                (("child", "service", "ordered_all"),),
            )
        self.assertEqual(raised.exception.reason_code, "RESOURCE_SELECTION_CYCLE")
        self.assertEqual(
            reconciler._selected_resources("missing", "service", "ordered_all"),
            ([], []),
        )
        self.assertEqual(
            reconciler._selected_resources("platform", "service", "ordered_all"),
            ([], []),
        )
        selected, _ = reconciler._selected_resources(
            "child", "service", "ordered_all",
        )
        self.assertEqual(selected, [child_row, parent_row])
        first, _ = reconciler._selected_resources(
            "child", "service", "classloader_first",
        )
        self.assertEqual(first, [child_row])
        reconciler.realms["fallback"] = {
            "identity": "fallback", "kind": "application",
            "parent": "", "delegation": "",
        }
        reconciler.resource_candidates_by_realm_name[("fallback", "service")] = [
            child_row
        ]
        fallback, _ = reconciler._selected_resources(
            "fallback", "service", "ordered_all",
        )
        self.assertEqual(fallback, [child_row])

        reconciler.entrypoint_realms = ("app",)
        reconciler.resource_categories_by_name = {
            "one": {"build_metadata"},
            "ambiguous": {"a", "b"},
        }
        reconciler.resource_candidates_by_realm_name = {
            ("app", "one"): [{
                "artifact_instance_identity": "artifact",
                "physical_entry_identity": "entry",
                "content_sha256": "sha",
                "normalized_resource_digest": "normalized",
                "resource_semantic_json": "",
            }],
        }
        reconciler.artifacts = {
            "artifact": {
                "runtime_classpath_index": 2,
                "runtime_code_source_origin_identity": "origin",
            },
        }
        records = reconciler._resource_selections()
        by_name = {record["resource_name"]: record for record in records}
        self.assertEqual(by_name["one"]["resource_selection_status"], "resolved")
        self.assertEqual(by_name["one"]["coverage_status"], "complete")
        self.assertEqual(by_name["ambiguous"]["resource_selection_status"], "missing")
        self.assertEqual(by_name["ambiguous"]["coverage_status"], "partial")
        self.assertIn("resource_category_ambiguous", by_name["ambiguous"]["coverage_gaps"])
        self.assertIn("resource_semantics_unregistered", by_name["ambiguous"]["coverage_gaps"])

    def test_platform_realm_and_provider_selection_matrix(self):
        reconciler = blank_reconciler()
        platform_class = platform_fact()
        reconciler.platform = FakePlatform({"java/lang/Object": platform_class})
        self.assertEqual(reconciler._platform_realm(), "platform")
        no_platform = blank_reconciler()
        no_platform.realms = {"app": {"kind": "application"}}
        self.assertEqual(no_platform._platform_realm(), "platform")

        missing = reconciler._provider("platform", "missing/Type")
        self.assertEqual(missing["class_provider_status"], "missing")
        found = reconciler._provider("unknown", "java/lang/Object")
        self.assertEqual(found["class_provider_status"], "resolved")
        self.assertIs(found, reconciler._provider("unknown", "java/lang/Object"))
        with self.assertRaises(rr.RuntimeReconciliationError) as raised:
            reconciler._provider("app", "Cycle", (("app", "Cycle"),))
        self.assertEqual(raised.exception.reason_code, "PROVIDER_RESOLUTION_CYCLE")

        reconciler.artifacts = {
            "own": {"runtime_classpath_index": 1},
            "tie-a": {"runtime_classpath_index": 0},
            "tie-b": {"runtime_classpath_index": 0},
            "later": {"runtime_classpath_index": 2},
        }
        reconciler.effective_candidates = {
            "app": {
                "Own": [{
                    "artifact_instance_identity": "own",
                    "class_variant_identity": "own-v",
                }],
                "Tied": [
                    {"artifact_instance_identity": "tie-a", "class_variant_identity": "a"},
                    {"artifact_instance_identity": "tie-b", "class_variant_identity": "b"},
                ],
                "Ordered": [
                    {"artifact_instance_identity": "own", "class_variant_identity": "first"},
                    {"artifact_instance_identity": "later", "class_variant_identity": "later"},
                ],
            },
        }
        own = reconciler._provider("app", "Own")
        self.assertEqual(own["selected_class_variant_identity"], "own-v")
        tied = reconciler._provider("app", "Tied")
        self.assertEqual(tied["class_provider_status"], "ambiguous")
        ordered = reconciler._provider("app", "Ordered")
        self.assertEqual(ordered["selected_class_variant_identity"], "first")

        reconciler.realms["child"] = {
            "identity": "child", "kind": "application", "parent": "platform",
            "delegation": "child_first",
        }
        reconciler.effective_candidates["child"] = {
            "ChildOwn": [{
                "artifact_instance_identity": "own",
                "class_variant_identity": "child-own-v",
            }],
        }
        child_own = reconciler._provider("child", "ChildOwn")
        self.assertEqual(child_own["selected_class_variant_identity"], "child-own-v")
        delegated = reconciler._provider("child", "java/lang/Object")
        self.assertEqual(delegated["class_provider_status"], "resolved")
        absent = reconciler._provider("child", "missing/Type")
        self.assertEqual(absent["class_provider_status"], "missing")

        parent_first = blank_reconciler()
        parent_first.platform = FakePlatform({"java/lang/Object": platform_class})
        parent_first.effective_candidates = {"app": {}}
        delegated = parent_first._provider("app", "java/lang/Object")
        self.assertEqual(delegated["initiating_loader_realm_identity"], "app")
        parent_first.realms["fallback"] = {
            "identity": "fallback", "kind": "application", "parent": "",
            "delegation": "parent_first",
        }
        parent_first.effective_candidates["fallback"] = {}
        self.assertEqual(
            parent_first._provider("fallback", "missing/Type")[
                "class_provider_status"
            ],
            "missing",
        )

    def test_class_fact_failure_status_and_security_matrix(self):
        reconciler = blank_reconciler()
        local = {"class_name": "Local"}
        reconciler.class_by_variant = {"local": local}
        self.assertIs(
            reconciler._class_fact(resolved_provider("Local", variant="local")),
            local,
        )
        platform = platform_fact("Platform", variant="platform-v")
        reconciler.platform = FakePlatform({"Platform": platform})
        self.assertEqual(
            reconciler._class_fact(
                resolved_provider("Platform", variant="platform-v")
            ),
            platform.fact,
        )
        self.assertIsNone(reconciler._class_fact(
            resolved_provider("Platform", variant="different")
        ))
        self.assertIsNone(reconciler._class_fact(
            resolved_provider("Missing", variant="missing")
        ))
        self.assertIsNone(reconciler._class_fact(
            resolved_provider("", variant="")
        ))

        cases = {
            "UnsupportedClassVersionError": "unsupported_class_version",
            "ClassFormatError": "class_format_error",
            "NoClassDefFoundError": "dependency_linkage_failed",
            "ClassNotFoundException": "dependency_linkage_failed",
            "TypeNotPresentException": "dependency_linkage_failed",
            "IllegalAccessError": "module_access_failed",
            "InaccessibleObjectException": "module_access_failed",
            "VerifyError": "verification_failed",
            "": "verification_failed",
        }
        for failure, expected in cases.items():
            with self.subTest(failure=failure):
                self.assertEqual(
                    reconciler._definition_status_from_failure(failure), expected,
                )

        resources = []
        reconciler.store = SimpleNamespace(rows=lambda *_args, **_kwargs: resources)
        reconciler._artifact_manifest = lambda _identity: {}
        self.assertFalse(reconciler._artifact_security_unsupported("artifact"))
        self.assertFalse(reconciler._artifact_security_unsupported("artifact"))

        orphan = blank_reconciler()
        orphan.store = SimpleNamespace(rows=lambda *_args, **_kwargs: [{
            "resource_name": "META-INF/BOOT.SF",
        }])
        orphan._artifact_manifest = lambda _identity: {}
        self.assertFalse(orphan._artifact_security_unsupported("orphan-sf"))

        signed = blank_reconciler()
        signed.store = SimpleNamespace(rows=lambda *_args, **_kwargs: [{
            "resource_name": "META-INF/APP.RSA",
        }])
        signed._artifact_manifest = lambda _identity: {}
        self.assertTrue(signed._artifact_security_unsupported("signed"))
        signed.capability = rr.RuntimeCapabilityPolicy(signed_artifacts_supported=True)
        self.assertFalse(signed._artifact_security_unsupported("signed-supported"))

        sealed = blank_reconciler()
        sealed.store = SimpleNamespace(rows=lambda *_args, **_kwargs: [])
        sealed._artifact_manifest = lambda _identity: {"sealed": ["false", "TRUE"]}
        self.assertTrue(sealed._artifact_security_unsupported("sealed"))
        sealed.capability = rr.RuntimeCapabilityPolicy(sealed_packages_supported=True)
        self.assertFalse(sealed._artifact_security_unsupported("sealed-supported"))

    def test_class_info_local_platform_missing_and_cache(self):
        reconciler = blank_reconciler()
        local_fact = {
            "class_name": "Local", "class_access": None,
            "super_name": None, "interfaces": None,
            "nest_host": None, "nest_members": None,
        }
        reconciler.class_by_variant = {"local": local_fact}
        reconciler.members_by_variant = {"local": [{"member_identity": "local-member"}]}
        local_provider = resolved_provider("Local", variant="local")
        local = reconciler._class_info(local_provider)
        self.assertEqual(local["members"], [{"member_identity": "local-member"}])
        self.assertEqual(local["access_flags"], 0)
        self.assertIs(local, reconciler._class_info(local_provider))

        none_reconciler = blank_reconciler()
        none_reconciler._class_fact = lambda _provider: None
        self.assertIsNone(none_reconciler._class_info(local_provider))
        self.assertIsNone(none_reconciler._class_info(local_provider))

        platform = platform_fact("Platform", module="demo.module", variant="pv")
        platform.fact.update({
            "class_access": rr.ACC_PUBLIC,
            "super_name": "java/lang/Object",
            "interfaces": ["Interface"],
            "nest_host": "Host",
            "nest_members": ["Member"],
            "fields": [{"name": "field", "descriptor": "I", "access": None}],
            "methods": [
                {"contract": {
                    "name": "method", "descriptor": "()V", "access": rr.ACC_PUBLIC,
                }},
                {"name": "fallback", "descriptor": "()I", "access": 0},
            ],
        })
        platform_reconciler = blank_reconciler()
        platform_reconciler.platform = FakePlatform({"Platform": platform})
        platform_provider = resolved_provider("Platform", variant="pv")
        info = platform_reconciler._class_info(platform_provider)
        self.assertEqual(info["module_name"], "demo.module")
        self.assertEqual({item["member_kind"] for item in info["members"]}, {"field", "method"})

        missing_platform = blank_reconciler()
        missing_platform._class_fact = lambda _provider: platform.fact
        missing_platform.platform = FakePlatform()
        self.assertIsNone(missing_platform._class_info(platform_provider))
        empty_provider = resolved_provider(
            "Platform", realm="", variant="pv",
        )
        empty_provider["selected_defining_loader_realm_identity"] = ""
        empty_info_reconciler = blank_reconciler()
        empty_info_reconciler.platform = FakePlatform({"Platform": platform})
        self.assertEqual(
            empty_info_reconciler._class_info(empty_provider)[
                "defining_loader_realm_identity"
            ],
            "",
        )
        empty_variant = blank_reconciler()
        empty_variant.class_by_variant = {"": local_fact}
        empty_variant.members_by_variant = {"": []}
        provider_without_variant = resolved_provider("Local", variant="")
        self.assertEqual(
            empty_variant._class_info(provider_without_variant)[
                "class_variant_identity"
            ],
            "",
        )

    def test_symbolic_member_resolution_parents_cache_and_cycles(self):
        reconciler = blank_reconciler()
        resolved = resolved_provider()
        reconciler._provider = lambda *_args: resolved
        reconciler.definition_records = {("app", "demo/Api"): definition()}
        member = {
            "member_identity": "member", "member_kind": "method",
            "member_name": "m", "descriptor": "()V",
        }
        infos = {
            "demo/Api": {
                "members": [member], "super_name": "Parent",
                "interfaces": ("Interface",),
                "defining_loader_realm_identity": "app",
            },
            "Parent": {
                "members": [], "super_name": None, "interfaces": (),
                "defining_loader_realm_identity": "app",
            },
        }
        reconciler._class_info = lambda provider: infos.get(provider["class_name"])
        self.assertEqual(
            reconciler._resolve_symbolic_member("app", "demo/Api", "method", "m", "()V")[0],
            member,
        )
        self.assertEqual(
            reconciler._resolve_symbolic_member("app", "demo/Api", "method", "m", "()V")[0],
            member,
        )
        self.assertGreater(reconciler._symbolic_member_cache_hits, 0)
        self.assertEqual(
            reconciler._resolve_symbolic_member_uncached(
                "app", "demo/Api", "method", "m", "()V", (("app", "demo/Api"),),
            ),
            (None, None),
        )

        unresolved = blank_reconciler()
        unresolved._provider = lambda *_args: {
            "class_provider_status": "missing",
        }
        self.assertIsNone(unresolved._resolve_symbolic_member_uncached(
            "app", "Missing", "method", "m", "()V",
        )[0])

        failed = blank_reconciler()
        failed_provider = resolved_provider()
        failed._provider = lambda *_args: failed_provider
        failed.definition_records = {("app", "demo/Api"): definition("failed", load_status="failed")}
        self.assertIsNone(failed._resolve_symbolic_member_uncached(
            "app", "demo/Api", "method", "m", "()V",
        )[0])

        no_info = blank_reconciler()
        no_info._provider = lambda *_args: resolved
        no_info.definition_records = {("app", "demo/Api"): definition()}
        no_info._class_info = lambda _provider: None
        self.assertIsNone(no_info._resolve_symbolic_member_uncached(
            "app", "demo/Api", "method", "m", "()V",
        )[0])

        recursive = blank_reconciler()
        providers = {
            "Child": resolved_provider("Child"),
            "Parent": resolved_provider("Parent"),
            "Interface": resolved_provider("Interface"),
        }
        recursive._provider = lambda _realm, name: providers[name]
        recursive.definition_records = {
            ("app", name): definition() for name in providers
        }
        target = dict(member, member_kind="field", member_name="f", descriptor="I")
        recursive._class_info = lambda provider: {
            "Child": {
                "members": [], "super_name": "Parent",
                "interfaces": ("", "Interface"),
                "defining_loader_realm_identity": "app",
            },
            "Parent": {
                "members": [], "super_name": None, "interfaces": (),
                "defining_loader_realm_identity": "app",
            },
            "Interface": {
                "members": [target], "super_name": None, "interfaces": (),
                "defining_loader_realm_identity": "app",
            },
        }[provider["class_name"]]
        self.assertEqual(recursive._resolve_symbolic_member_uncached(
            "app", "Child", "field", "f", "I",
        )[0], target)
        self.assertIsNone(recursive._resolve_symbolic_member_uncached(
            "app", "Child", "method", "<init>", "()V",
        )[0])
        self.assertIsNone(recursive._resolve_symbolic_member_uncached(
            "app", "Child", "method", "missing", "()V",
        )[0])
        self.assertIsNone(recursive._resolve_symbolic_member(
            "app", "Child", "method", "missing", "()V",
            (("other", "Visited"),),
        )[0])
        self.assertIsNone(recursive._resolve_symbolic_member_uncached(
            "app", "Child", "field", "f", "J",
        )[0])

        with patch.object(rr, "_SYMBOLIC_MEMBER_CACHE_MAX_ENTRIES", 1):
            reconciler._resolve_symbolic_member("app", "Other", "method", "x", "()V")
        self.assertLessEqual(len(reconciler._symbolic_member_root_cache), 1)

    def test_interface_object_fallback_rejects_static_and_private_methods(self):
        reconciler = blank_reconciler()
        providers = {
            name: resolved_provider(name) for name in (
                "demo/Api", "demo/ParentApi", "java/lang/Object",
            )
        }
        reconciler._provider = lambda _realm, name: providers[name]
        reconciler.definition_records = {
            ("app", name): definition() for name in providers
        }
        public_instance = {
            "member_identity": "object-public", "member_kind": "method",
            "member_name": "publicMethod", "descriptor": "()V",
            "access_flags": rr.ACC_PUBLIC,
        }
        private_instance = {
            "member_identity": "object-private", "member_kind": "method",
            "member_name": "privateMethod", "descriptor": "()V",
            "access_flags": rr.ACC_PRIVATE,
        }
        public_static = {
            "member_identity": "object-static", "member_kind": "method",
            "member_name": "staticMethod", "descriptor": "()V",
            "access_flags": rr.ACC_PUBLIC | rr.ACC_STATIC,
        }
        package_instance = {
            "member_identity": "object-package", "member_kind": "method",
            "member_name": "packageMethod", "descriptor": "()V",
        }
        inherited = {
            "member_identity": "parent-interface", "member_kind": "method",
            "member_name": "inherited", "descriptor": "()V",
            "access_flags": rr.ACC_PUBLIC,
        }
        infos = {
            "demo/Api": {
                "members": [], "access_flags": rr.ACC_INTERFACE,
                "super_name": "java/lang/Object",
                "interfaces": ("demo/ParentApi",),
                "defining_loader_realm_identity": "app",
            },
            "demo/ParentApi": {
                "members": [inherited], "access_flags": rr.ACC_INTERFACE,
                "super_name": "java/lang/Object", "interfaces": (),
                "defining_loader_realm_identity": "app",
            },
            "java/lang/Object": {
                "members": [
                    public_instance, private_instance, public_static,
                    package_instance,
                ],
                "access_flags": rr.ACC_PUBLIC,
                "super_name": None, "interfaces": (),
                "defining_loader_realm_identity": "app",
            },
        }
        reconciler._class_info = lambda provider: infos[provider["class_name"]]

        self.assertEqual(reconciler._resolve_symbolic_member_uncached(
            "app", "demo/Api", "method", "publicMethod", "()V",
        )[0], public_instance)
        self.assertEqual(reconciler._resolve_symbolic_member_uncached(
            "app", "demo/Api", "method", "inherited", "()V",
        )[0], inherited)
        for name in ("privateMethod", "staticMethod", "packageMethod"):
            self.assertIsNone(reconciler._resolve_symbolic_member_uncached(
                "app", "demo/Api", "method", name, "()V",
            )[0])

    def test_ancestor_virtual_dispatch_and_member_access_matrix(self):
        reconciler = blank_reconciler()
        providers = {
            "Child": resolved_provider("Child"),
            "Parent": resolved_provider("Parent"),
            "Interface": resolved_provider("Interface"),
            "Missing": {"class_provider_status": "missing"},
        }
        reconciler._provider = lambda _realm, name: providers[name]
        infos = {
            "Child": {
                "super_name": "Parent", "interfaces": ("Interface",),
                "defining_loader_realm_identity": "app",
                "access_flags": 0, "members": [],
            },
            "Parent": {
                "super_name": None, "interfaces": (),
                "defining_loader_realm_identity": "app",
                "access_flags": 0, "members": [],
            },
            "Interface": {
                "super_name": None, "interfaces": (),
                "defining_loader_realm_identity": "app",
                "access_flags": rr.ACC_INTERFACE, "members": [],
            },
        }
        reconciler._class_info = lambda provider: infos.get(provider.get("class_name"))
        ancestors = reconciler._ancestor_types("app", "Child")
        self.assertEqual(ancestors, frozenset({"Child", "Parent", "Interface"}))
        self.assertIs(ancestors, reconciler._ancestor_types("app", "Child"))
        self.assertEqual(
            reconciler._ancestor_types("app", "Child", (("app", "Child"),)),
            ancestors,
        )
        self.assertEqual(
            reconciler._ancestor_types("app", "Missing"), frozenset({"Missing"}),
        )
        visiting = blank_reconciler()
        self.assertEqual(
            visiting._ancestor_types(
                "app", "Cycle", (("app", "Cycle"),),
            ),
            frozenset({"Cycle"}),
        )
        self.assertTrue(reconciler._is_subtype("app", "Child", "Parent"))

        dispatch = blank_reconciler()
        dispatch.definition_records = {
            ("app", "Concrete"): definition(),
            ("app", "Abstract"): definition(),
            ("app", "Failed"): definition("failed", load_status="failed"),
            ("app", "NoInfo"): definition(),
            ("app", "NoTarget"): definition(),
        }
        dispatch._provider = lambda _realm, name: resolved_provider(name)
        dispatch._class_info = lambda provider: {
            "Concrete": {"access_flags": 0},
            "Abstract": {"access_flags": rr.ACC_ABSTRACT},
            "Failed": {"access_flags": 0},
            "NoInfo": None,
            "NoTarget": {"access_flags": 0},
        }[provider["class_name"]]
        dispatch._ancestor_types = lambda _realm, name: frozenset({name, "Owner"})
        dispatch._resolve_symbolic_member = lambda _realm, name, *_args: (
            ({"member_identity": "target" if name == "Concrete" else "target-2"}, None)
            if name not in {"Failed", "NoTarget"} else (None, None)
        )
        targets = dispatch._virtual_dispatch_targets(
            (
                ("app", "Concrete"), ("app", "Abstract"),
                ("app", "Failed"), ("app", "MissingDefinition"),
                ("app", "NoInfo"), ("app", "NoTarget"),
            ),
            "Owner", "m", "()V",
        )
        self.assertEqual(targets, ("target",))
        self.assertIs(targets, dispatch._virtual_dispatch_targets((), "Owner", "m", "()V"))

        access = blank_reconciler()
        access._class_info = lambda _provider: {"module_name": "demo.module"}
        access.platform = FakePlatform(exports={"demo.module": frozenset({"demo"})})
        public = {"access_flags": rr.ACC_PUBLIC, "class_name": "demo/Api"}
        provider_row = resolved_provider("demo/Api")
        self.assertTrue(access._member_accessible("x/Caller", "app", public, provider_row))
        access.platform = FakePlatform(exports={"demo.module": frozenset()})
        self.assertFalse(access._member_accessible("x/Caller", "app", public, provider_row))
        access._class_info = lambda _provider: {"module_name": ""}
        self.assertTrue(access._member_accessible("x/Caller", "app", public, provider_row))
        access._class_info = lambda _provider: None
        self.assertTrue(access._member_accessible("x/Caller", "app", public, provider_row))
        private = {"access_flags": rr.ACC_PRIVATE, "class_name": "demo/Api"}
        access._validated_nestmates = lambda *_args: True
        self.assertTrue(access._member_accessible("x/Caller", "app", private, provider_row))
        access._validated_nestmates = lambda *_args: False
        self.assertTrue(access._member_accessible("demo/Api", "app", private, provider_row))
        self.assertFalse(access._member_accessible(
            "demo/Api", "different-realm", private, provider_row,
        ))
        protected = {"access_flags": rr.ACC_PROTECTED, "class_name": "demo/Api"}
        access._is_subtype = lambda *_args: True
        self.assertTrue(access._member_accessible("x/Caller", "app", protected, provider_row))
        access._is_subtype = lambda *_args: False
        self.assertFalse(access._member_accessible("x/Caller", "app", protected, provider_row))
        self.assertTrue(access._member_accessible(
            "demo/Caller", "app", protected, provider_row,
        ))
        package = {"access_flags": 0, "class_name": "demo/Api"}
        self.assertTrue(access._member_accessible("demo/Caller", "app", package, provider_row))
        self.assertFalse(access._member_accessible("x/Caller", "app", package, provider_row))

    def test_validated_nestmate_fail_closed_matrix(self):
        reconciler = blank_reconciler()
        for arguments in (
            ("", "app", "Owner", "app"),
            ("Caller", "app", "", "app"),
            ("demo/Caller", "a", "demo/Owner", "b"),
            ("a/Caller", "app", "b/Owner", "app"),
        ):
            self.assertFalse(reconciler._validated_nestmates(*arguments))

        providers = {
            "demo/Caller": resolved_provider("demo/Caller"),
            "demo/Owner": resolved_provider("demo/Owner"),
            "demo/Host": resolved_provider("demo/Host"),
        }
        reconciler._provider = lambda _realm, name: providers[name]
        infos = {
            "demo/Caller": {"nest_host": "demo/Host", "class_name": "demo/Caller"},
            "demo/Owner": {"nest_host": "demo/Host", "class_name": "demo/Owner"},
            "demo/Host": {
                "nest_host": "", "class_name": "demo/Host",
                "nest_members": ("demo/Caller", "demo/Owner"),
            },
        }
        reconciler._class_info = lambda provider: infos.get(provider["class_name"])
        reconciler.definition_records = {("app", "demo/Host"): definition()}
        self.assertTrue(reconciler._validated_nestmates(
            "demo/Caller", "app", "demo/Owner", "app",
        ))

        providers["demo/Caller"] = {"class_provider_status": "missing"}
        self.assertFalse(reconciler._validated_nestmates(
            "demo/Caller", "app", "demo/Owner", "app",
        ))
        providers["demo/Caller"] = resolved_provider("demo/Caller")
        providers["demo/Owner"] = {"class_provider_status": "missing"}
        self.assertFalse(reconciler._validated_nestmates(
            "demo/Caller", "app", "demo/Owner", "app",
        ))
        providers["demo/Owner"] = resolved_provider("demo/Owner")
        infos["demo/Caller"] = None
        self.assertFalse(reconciler._validated_nestmates(
            "demo/Caller", "app", "demo/Owner", "app",
        ))
        infos["demo/Caller"] = {"nest_host": "demo/Host", "class_name": "demo/Caller"}
        infos["demo/Owner"] = None
        self.assertFalse(reconciler._validated_nestmates(
            "demo/Caller", "app", "demo/Owner", "app",
        ))
        infos["demo/Owner"] = {"nest_host": "demo/Other", "class_name": "demo/Owner"}
        self.assertFalse(reconciler._validated_nestmates(
            "demo/Caller", "app", "demo/Owner", "app",
        ))

        infos["demo/Owner"] = {"nest_host": "demo/Host", "class_name": "demo/Owner"}
        providers["demo/Host"] = {"class_provider_status": "missing"}
        self.assertFalse(reconciler._validated_nestmates(
            "demo/Caller", "app", "demo/Owner", "app",
        ))
        providers["demo/Host"] = resolved_provider("demo/Host")
        reconciler.definition_records = {}
        self.assertFalse(reconciler._validated_nestmates(
            "demo/Caller", "app", "demo/Owner", "app",
        ))
        reconciler.definition_records = {("app", "demo/Host"): definition()}
        infos["demo/Host"] = None
        self.assertFalse(reconciler._validated_nestmates(
            "demo/Caller", "app", "demo/Owner", "app",
        ))
        infos["demo/Host"] = {"nest_host": "Other", "class_name": "demo/Host", "nest_members": ()}
        self.assertFalse(reconciler._validated_nestmates(
            "demo/Caller", "app", "demo/Owner", "app",
        ))
        infos["demo/Host"] = {
            "nest_host": "", "class_name": "different/Host", "nest_members": (),
        }
        self.assertFalse(reconciler._validated_nestmates(
            "demo/Caller", "app", "demo/Owner", "app",
        ))
        infos["demo/Host"] = {
            "nest_host": "", "class_name": "", "nest_members": (),
        }
        self.assertFalse(reconciler._validated_nestmates(
            "demo/Caller", "app", "demo/Owner", "app",
        ))

    def test_opcode_and_type_resolution_matrix(self):
        static_member = {"access_flags": rr.ACC_STATIC}
        instance_member = {"access_flags": 0}
        for opcode in (178, 179, 184):
            self.assertTrue(RuntimeReconciler._opcode_compatible(
                {"opcode": opcode, "edge_json": "{}"}, static_member,
            ))
            self.assertFalse(RuntimeReconciler._opcode_compatible(
                {"opcode": opcode, "edge_json": "{}"}, instance_member,
            ))
        for opcode in (180, 181, 182, 183, 185):
            self.assertFalse(RuntimeReconciler._opcode_compatible(
                {"opcode": opcode, "edge_json": "{}"}, static_member,
            ))
            self.assertTrue(RuntimeReconciler._opcode_compatible(
                {"opcode": opcode, "edge_json": "{}"}, instance_member,
            ))
        for payload, member, expected in (
            ({"tag": 6}, static_member, True),
            ({"bootstrap": {"tag": 6}}, instance_member, False),
            ({"tag": 5}, instance_member, True),
            ({"tag": 7}, static_member, False),
            ({"tag": 0}, static_member, True),
            ({}, instance_member, True),
        ):
            self.assertEqual(RuntimeReconciler._opcode_compatible(
                {"opcode": None, "edge_json": json.dumps(payload)}, member,
            ), expected)
        self.assertTrue(RuntimeReconciler._opcode_compatible(
            {"opcode": None, "edge_json": ""}, instance_member,
        ))

        reconciler = blank_reconciler()
        providers = {
            "Missing": {"class_provider_status": "missing", "provider_binding_identity": "missing"},
            "Failed": resolved_provider("Failed", identity="failed-provider"),
            "Ready": resolved_provider("Ready", identity="ready-provider"),
        }
        reconciler._provider = lambda _realm, name: providers[name]
        reconciler.definition_records = {
            ("app", "Failed"): definition("failed", load_status="failed"),
            ("app", "Ready"): definition(),
        }
        for owner, expected in (
            ("", "primitive_or_array_type"),
            ("[I", "primitive_or_array_type"),
            ("Missing", "unresolved"),
            ("Failed", "class_definition_failed"),
            ("Ready", "resolved"),
        ):
            record = reconciler._type_resolution({
                "direct_edge_identity": f"edge-{owner}",
                "symbolic_owner": owner,
                "symbolic_descriptor": "Lx;",
                "edge_json": "",
            }, "app")
            self.assertEqual(record["type_resolution_status"], expected)

    def test_initialization_helpers_and_resolution_matrix(self):
        reconciler = blank_reconciler()
        providers = {
            name: resolved_provider(name) for name in (
                "Class", "Super", "Interface", "Nested", "Missing",
            )
        }
        providers["Missing"] = {"class_provider_status": "missing"}
        reconciler._provider = lambda _realm, name: providers[name]
        reconciler.definition_records = {
            ("app", name): definition() for name in ("Class", "Super", "Interface", "Nested")
        }
        clinit = {
            "member_identity": "clinit", "member_kind": "method",
            "member_name": "<clinit>", "descriptor": "()V", "access_flags": rr.ACC_STATIC,
        }
        default_method = {
            "member_identity": "default", "member_kind": "method",
            "member_name": "m", "descriptor": "()V", "access_flags": 0,
        }
        field_member = {
            "member_identity": "field", "member_kind": "field",
            "member_name": "f", "descriptor": "I", "access_flags": 0,
        }
        infos = {
            "Class": {
                "defining_loader_realm_identity": "app", "access_flags": 0,
                "super_name": "Super", "interfaces": ("Interface",),
                "members": [clinit],
            },
            "Super": {
                "defining_loader_realm_identity": "app", "access_flags": 0,
                "super_name": None, "interfaces": (), "members": [],
            },
            "Interface": {
                "defining_loader_realm_identity": "app", "access_flags": rr.ACC_INTERFACE,
                "super_name": None, "interfaces": ("Nested",),
                "members": [field_member, default_method, clinit],
            },
            "Nested": {
                "defining_loader_realm_identity": "app", "access_flags": rr.ACC_INTERFACE,
                "super_name": None, "interfaces": (), "members": [],
            },
        }
        reconciler._class_info = lambda provider: infos.get(provider.get("class_name"))
        self.assertEqual(
            reconciler._default_interface_initializers("app", "Interface", {("app", "Interface")}),
            ([], True),
        )
        targets, complete = reconciler._default_interface_initializers("app", "Interface", set())
        self.assertTrue(complete)
        self.assertEqual(targets, ["clinit"])
        self.assertEqual(
            reconciler._default_interface_initializers("app", "Missing", set()),
            ([], False),
        )
        providers["ParentInterface"] = resolved_provider("ParentInterface")
        reconciler.definition_records[("app", "ParentInterface")] = definition()
        infos["ParentInterface"] = {
            "defining_loader_realm_identity": "app",
            "access_flags": rr.ACC_INTERFACE,
            "super_name": None,
            "interfaces": ("Missing", "Nested"),
            "members": [field_member],
        }
        self.assertEqual(
            reconciler._default_interface_initializers(
                "app", "ParentInterface", set(),
            ),
            ([], False),
        )
        missing_definition = resolved_provider("MissingDefinition")
        providers["MissingDefinition"] = missing_definition
        self.assertEqual(
            reconciler._default_interface_initializers(
                "app", "MissingDefinition", set(),
            ),
            ([], False),
        )
        providers["FailedDefinition"] = resolved_provider("FailedDefinition")
        reconciler.definition_records[("app", "FailedDefinition")] = definition(
            "failed", load_status="failed",
        )
        self.assertEqual(
            reconciler._default_interface_initializers(
                "app", "FailedDefinition", set(),
            ),
            ([], False),
        )
        self.assertFalse(reconciler._append_class_initialization_chain(
            "app", "FailedDefinition", set(), [],
        ))
        providers["Missing"] = resolved_provider("Missing")
        reconciler.definition_records[("app", "Missing")] = definition()
        self.assertEqual(
            reconciler._default_interface_initializers("app", "Missing", set()),
            ([], False),
        )

        chain = []
        self.assertTrue(reconciler._append_class_initialization_chain(
            "app", "Class", set(), chain,
        ))
        self.assertEqual(chain, ["clinit", "clinit"])
        self.assertTrue(reconciler._append_class_initialization_chain(
            "app", "Class", {("app", "Class")}, [],
        ))
        interface_chain = []
        self.assertTrue(reconciler._append_class_initialization_chain(
            "app", "Interface", set(), interface_chain,
        ))
        providers["BrokenSuper"] = resolved_provider("BrokenSuper")
        reconciler.definition_records[("app", "BrokenSuper")] = definition()
        infos["BrokenSuper"] = {
            "defining_loader_realm_identity": "app", "access_flags": 0,
            "super_name": "FailedDefinition", "interfaces": (), "members": [],
        }
        self.assertFalse(reconciler._append_class_initialization_chain(
            "app", "BrokenSuper", set(), [],
        ))
        providers["BrokenInterface"] = resolved_provider("BrokenInterface")
        reconciler.definition_records[("app", "BrokenInterface")] = definition()
        infos["BrokenInterface"] = {
            "defining_loader_realm_identity": "app", "access_flags": 0,
            "super_name": None,
            "interfaces": ("FailedDefinition", "Nested"),
            "members": [],
        }
        self.assertFalse(reconciler._append_class_initialization_chain(
            "app", "BrokenInterface", set(), [],
        ))
        providers["Missing"] = {"class_provider_status": "missing"}
        self.assertFalse(reconciler._append_class_initialization_chain(
            "app", "Missing", set(), [],
        ))
        providers["Missing"] = resolved_provider("Missing")
        reconciler.definition_records.pop(("app", "Missing"), None)
        self.assertFalse(reconciler._append_class_initialization_chain(
            "app", "Missing", set(), [],
        ))
        reconciler.definition_records[("app", "Missing")] = definition()
        self.assertFalse(reconciler._append_class_initialization_chain(
            "app", "Missing", set(), [],
        ))

        resolution = blank_reconciler()
        resolution._append_class_initialization_chain = (
            lambda realm, owner, visited, chain: chain.append("init") or False
        )
        resolution._resolve_symbolic_member = lambda *_args: (
            {"class_name": "Declared"},
            {"selected_defining_loader_realm_identity": "declaring"},
        )
        static = resolution._class_initialization_resolution({
            "direct_edge_identity": "static",
            "symbolic_owner": "Owner",
            "edge_json": json.dumps({
                "trigger_kind": "invokestatic",
                "trigger_member_name": "m",
                "trigger_member_descriptor": "()V",
            }),
        }, "app", "Caller")
        self.assertEqual(static["initialized_owner"], "Declared")
        self.assertEqual(static["class_initialization_status"], "partial")
        already = resolution._class_initialization_resolution({
            "direct_edge_identity": "already",
            "symbolic_owner": "Caller",
            "edge_json": json.dumps({"trigger_kind": "new"}),
        }, "app", "Caller")
        self.assertEqual(
            already["class_initialization_status"],
            "not_applicable_already_initialized",
        )
        resolution._resolve_symbolic_member = lambda *_args: (None, None)
        field = resolution._class_initialization_resolution({
            "direct_edge_identity": "field",
            "symbolic_owner": "Owner",
            "edge_json": json.dumps({
                "trigger_kind": "getstatic",
                "trigger_member_name": "f",
                "trigger_member_descriptor": "I",
            }),
        }, "app", "Caller")
        self.assertEqual(field["initialized_owner"], "Owner")
        partial_member = dict(field)
        resolution._resolve_symbolic_member = lambda *_args: (
            {"class_name": "Declared"}, None,
        )
        unresolved_provider = resolution._class_initialization_resolution({
            "direct_edge_identity": "member-without-provider",
            "symbolic_owner": "",
            "edge_json": json.dumps({
                "trigger_kind": "putstatic",
                "trigger_member_name": "",
                "trigger_member_descriptor": "",
            }),
        }, "app", "Caller")
        self.assertEqual(unresolved_provider["initialized_owner"], "")
        empty_trigger = resolution._class_initialization_resolution({
            "direct_edge_identity": "empty-trigger",
            "symbolic_owner": "Owner",
            "edge_json": "",
        }, "app", "Caller")
        self.assertEqual(empty_trigger["trigger"], {})

    def test_member_loading_constraint_aggregate_matrix(self):
        reconciler = blank_reconciler()
        provider_rows = {
            ("caller", "Same"): resolved_provider("Same", realm="caller", identity="caller-same"),
            ("declaration", "Same"): resolved_provider("Same", realm="declaration", identity="decl-same"),
            ("caller", "Conflict"): resolved_provider("Conflict", realm="caller", identity="caller-conflict"),
            ("declaration", "Conflict"): resolved_provider("Conflict", realm="other", identity="decl-conflict"),
            ("caller", "Missing"): {"class_provider_status": "missing"},
            ("declaration", "Missing"): resolved_provider("Missing", realm="declaration"),
        }
        provider_rows[("caller", "Same")]["selected_defining_loader_realm_identity"] = "shared"
        provider_rows[("declaration", "Same")]["selected_defining_loader_realm_identity"] = "shared"
        reconciler._provider = lambda realm, name: provider_rows[(realm, name)]
        status, rows = reconciler._member_loading_constraints(
            "same-realm", "same-realm", ("Direct",),
        )
        self.assertEqual(status, "satisfied")
        self.assertEqual(rows[0]["evidence_kind"], "same_defining_loader")

        status, rows = reconciler._member_loading_constraints(
            "caller", "declaration", ("Same", "Missing", "Conflict"),
        )
        self.assertEqual(status, "deferred_conflict")
        self.assertEqual(
            {row["constraint_status"] for row in rows},
            {"satisfied", "unresolved", "deferred_conflict"},
        )
        missing = next(row for row in rows if row["class_name"] == "Missing")
        self.assertEqual(missing["caller_class_identity"], "")

        empty_rows = {
            ("caller", "Empty"): {
                "class_provider_status": "",
                "provider_binding_identity": "",
                "selected_defining_loader_realm_identity": "",
            },
            ("declaration", "Empty"): {
                "class_provider_status": "",
                "provider_binding_identity": "",
                "selected_defining_loader_realm_identity": "",
            },
        }
        reconciler._provider = lambda realm, name: empty_rows[(realm, name)]
        status, constraints = reconciler._member_loading_constraints(
            "caller", "declaration", ("Empty",),
        )
        self.assertEqual(status, "unresolved")
        self.assertEqual(constraints[0]["declaration_class_identity"], "")
        reconciler._provider = lambda realm, name: provider_rows[(realm, name)]
        status, rows = reconciler._member_loading_constraints(
            "caller", "declaration", ("Conflict", "Missing"),
        )
        self.assertEqual(status, "deferred_conflict")
        self.assertEqual(rows[-1]["constraint_status"], "unresolved")

    def test_build_definition_status_topology_and_verifier_matrix(self):
        reconciler = blank_reconciler()
        reconciler.store = SimpleNamespace(class_bytes=lambda _variant: b"class")
        reconciler.realms = {
            "platform": {"kind": "platform"},
            "app": {
                "kind": "application", "parent": "platform",
                "delegation": "parent_first", "module_mode": "unnamed",
            },
        }
        rows = {
            "parse": {
                "parse_status": "failed", "failure_kind": "bad",
                "class_major": 61, "artifact_instance_identity": "artifact",
            },
            "new": {
                "parse_status": "parsed", "failure_kind": "",
                "class_major": 99, "artifact_instance_identity": "artifact",
            },
            "ready": {
                "parse_status": "parsed", "failure_kind": "",
                "class_major": 61, "artifact_instance_identity": "artifact",
            },
            "link": {
                "parse_status": "parsed", "failure_kind": "",
                "class_major": 61, "artifact_instance_identity": "artifact",
            },
            "failure": {
                "parse_status": "parsed", "failure_kind": "",
                "class_major": 61, "artifact_instance_identity": "artifact",
            },
            "unavailable": {
                "parse_status": "parsed", "failure_kind": "",
                "class_major": 61, "artifact_instance_identity": "artifact",
            },
        }
        reconciler.class_by_variant = rows
        providers = {
            ("app", "Ambiguous"): {
                "class_provider_status": "ambiguous",
                "provider_binding_identity": "ambiguous-provider",
            },
            ("app", "Missing"): {
                "class_provider_status": "missing",
                "provider_binding_identity": "missing-provider",
            },
            ("app", "Platform"): resolved_provider(
                "Platform", variant="platform-variant",
            ),
        }
        for name, variant in (
            ("Parse", "parse"), ("New", "new"), ("Ready", "ready"),
            ("Link", "link"), ("Failure", "failure"),
            ("Unavailable", "unavailable"),
        ):
            providers[("app", name)] = resolved_provider(name, variant=variant)
        reconciler._provider = lambda realm, name: providers[(realm, name)]
        reconciler._artifact_security_unsupported = lambda _identity: False
        accumulator = CaptureAccumulator()
        outcomes = {
            "Ready": {"status": "definition_ready"},
            "Link": {
                "status": "failed", "failure_kind": "NoClassDefFoundError",
                "failure_phase": "member_linkage",
            },
            "Failure": {
                "status": "failed", "failure_kind": "ClassFormatError",
                "failure_phase": "load",
            },
        }
        universe = tuple(providers)
        with patch.object(rr, "verify_class_definitions", return_value=outcomes):
            reconciler._build_definitions(universe, accumulator)
        by_name = {
            record["class_name"]: record
            for kind, record in accumulator.items if kind == "class_definition"
        }
        self.assertEqual(by_name["Ambiguous"]["class_definition_status"], "ambiguous")
        self.assertEqual(by_name["Missing"]["class_definition_status"], "unsupported")
        self.assertEqual(by_name["Platform"]["class_definition_status"], "definition_ready")
        self.assertEqual(by_name["Parse"]["class_definition_status"], "class_format_error")
        self.assertEqual(by_name["New"]["class_definition_status"], "unsupported_class_version")
        self.assertEqual(by_name["Ready"]["class_load_status"], "ready")
        self.assertEqual(by_name["Link"]["class_load_status"], "ready")
        self.assertEqual(by_name["Failure"]["class_definition_status"], "class_format_error")
        self.assertEqual(by_name["Unavailable"]["class_definition_status"], "unsupported")
        self.assertIsInstance(
            reconciler.definition_records[("app", "Ready")],
            rr._DefinitionRuntimeRow,
        )

        def one_case(
            *, profile_payload=None, capability=None,
            artifact_security=False, realms=None, verifier=None,
            realm="app", class_row=None,
        ):
            case = blank_reconciler()
            case.store = SimpleNamespace(class_bytes=lambda _variant: b"class")
            case.profile.payload = profile_payload or dict(case.profile.payload)
            case.capability = capability or rr.RuntimeCapabilityPolicy()
            case.realms = realms or dict(reconciler.realms)
            case.class_by_variant = {"ready": class_row or rows["ready"]}
            case._provider = lambda _realm, _name: resolved_provider(
                "Ready", variant="ready",
            )
            case._artifact_security_unsupported = lambda _identity: artifact_security
            captured = CaptureAccumulator(("class_definition",))
            effect = verifier if isinstance(verifier, BaseException) else None
            returned = verifier if isinstance(verifier, dict) else {
                "Ready": {"status": "definition_ready"},
            }
            with patch.object(
                rr, "verify_class_definitions",
                side_effect=effect,
                return_value=returned,
            ):
                case._build_definitions(((realm, "Ready"),), captured)
            return case, captured.items[0][1]

        unsupported_security, record = one_case(profile_payload={
            **blank_reconciler().profile.payload,
            "runtime_security_and_package_sealing_policy_identity": "unsupported",
        })
        self.assertEqual(record["class_definition_status"], "security_failed")
        self.assertEqual(
            record["evidence"]["reason"],
            "runtime_security_policy_unsupported",
        )
        _case, record = one_case(artifact_security=True)
        self.assertEqual(record["evidence"]["reason"], "signed_or_sealed_artifact_unsupported")
        _case, record = one_case(profile_payload={
            **blank_reconciler().profile.payload,
            "agent_transformer_plugin_profile_identities": ["transformer"],
        })
        self.assertEqual(record["evidence"]["reason"], "transformer_profile_unsupported")
        _case, record = one_case(profile_payload={
            **blank_reconciler().profile.payload,
            "runtime_security_and_package_sealing_policy_identity": "",
        })
        self.assertEqual(record["class_definition_status"], "security_failed")
        _case, record = one_case(class_row={
            **rows["ready"], "class_major": None,
        })
        self.assertEqual(record["class_definition_status"], "definition_ready")

        empty_realm, record = one_case(realm="")
        self.assertEqual(record["class_definition_status"], "unsupported")
        self.assertIn("definition_topology_unsupported:", empty_realm.coverage_gaps)

        no_parent, record = one_case(realms={
            "platform": {"kind": "platform"},
            "app": {
                "delegation": "parent_first", "module_mode": "unnamed",
                "parent": "",
            },
        })
        self.assertEqual(record["class_definition_status"], "definition_ready")
        self.assertFalse(any(
            gap.startswith("definition_topology_unsupported:")
            for gap in no_parent.coverage_gaps
        ))

        for realms in (
            {
                "platform": {"kind": "platform"},
                "app": {"delegation": "child_first", "parent": "platform"},
            },
            {
                "platform": {"kind": "platform"},
                "app": {"module_mode": "named", "parent": "platform"},
            },
            {
                "platform": {"kind": "platform"},
                "app": {"parent": "outside"},
            },
            {
                "platform": {"kind": "platform"},
                "app": {"parent": "loop"},
                "loop": {"parent": "app"},
            },
        ):
            with self.subTest(realms=realms):
                case, record = one_case(realms=realms)
                self.assertEqual(record["class_definition_status"], "unsupported")
                self.assertTrue(any(
                    gap.startswith("definition_topology_unsupported:")
                    for gap in case.coverage_gaps
                ))

        verifier_error = rr.ClassDefinitionVerifierError("VERIFIER_FAILED", "detail")
        case, record = one_case(verifier=verifier_error)
        self.assertEqual(record["class_definition_status"], "unsupported")
        self.assertIn(
            "definition_verifier_failed:app:VERIFIER_FAILED",
            case.coverage_gaps,
        )

    def test_resolve_edges_complete_decision_matrix(self):
        def edge(identity, owner="Resolved", **overrides):
            record = {
                "direct_edge_identity": identity,
                "caller_member_identity": "caller-member",
                "caller_artifact_instance_identity": "artifact",
                "instruction_index": 0,
                "bytecode_offset": 0,
                "edge_kind": "method",
                "opcode": 184,
                "symbolic_owner": owner,
                "symbolic_name": "m",
                "symbolic_descriptor": "()V",
                "edge_json": "{}",
            }
            record.update(overrides)
            return record

        edges = [
            edge("missing-caller", caller_member_identity="absent"),
            edge("shadowed", caller_member_identity="shadow-member"),
            edge("wrong-artifact", caller_artifact_instance_identity="other-artifact"),
            edge("type", edge_kind="type", symbolic_owner=""),
            edge("init", edge_kind="class_init", edge_json=""),
            edge("init-empty-caller", edge_kind="class_init", edge_json="{}",
                 caller_member_identity="empty-caller-member"),
            edge("constant", edge_kind="ldc_constant_dynamic", edge_json=""),
            edge("constant-json", edge_kind="ldc_constant_dynamic",
                 edge_json=json.dumps({"value": 1})),
            edge("ambiguous", "Ambiguous"),
            edge("missing", "Missing"),
            edge("failed", "Failed"),
            edge("no-member", "NoMember"),
            edge("illegal", "Illegal"),
            edge("deferred", "Deferred", edge_json=json.dumps({
                rr.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: ["Type"],
            })),
            edge("constraint-unresolved", "ConstraintUnresolved"),
            edge("incompatible", "Incompatible"),
            edge("static", "Static"),
            edge("zero-opcode", "Static", opcode=None, edge_json=""),
            edge("empty-caller", "Static",
                 caller_member_identity="empty-caller-member"),
            edge("field", "Field", edge_kind="field", opcode=178),
            edge("handle-field", "Field", edge_kind="ldc_handle", opcode=None,
                 edge_json=json.dumps({"tag": 1})),
            edge("bootstrap-field", "Field", edge_kind="invokedynamic_bootstrap",
                 opcode=None, edge_json=json.dumps({"bootstrap": {"tag": 2}})),
            edge("bootstrap-scalar", "Static", edge_kind="ldc_handle", opcode=None,
                 edge_json=json.dumps({"bootstrap": "invalid"})),
            edge("array", "[LComponent;", opcode=182, symbolic_name="clone",
                 symbolic_descriptor="()Ljava/lang/Object;"),
            edge("primitive-array", "[I", opcode=182, symbolic_name="clone",
                 symbolic_descriptor="()Ljava/lang/Object;"),
            edge("final-member", "FinalMember", opcode=182),
            edge("final-class", "FinalClass", opcode=182),
            edge("virtual-none", "VirtualNone", opcode=182),
            edge("virtual-one", "VirtualOne", opcode=182),
            edge("virtual-many", "VirtualMany", opcode=185),
        ]

        reconciler = blank_reconciler()
        reconciler.store = SimpleNamespace(
            connection=SimpleNamespace(execute=lambda _query: edges),
        )
        reconciler.artifacts = {
            "artifact": {"loader_realm_identity": "app"},
        }
        reconciler.classes = [
            {
                "artifact_instance_identity": "outside",
                "class_name": "Outside", "class_variant_identity": "outside-v",
            },
            {
                "artifact_instance_identity": "artifact",
                "class_name": "Unselected", "class_variant_identity": "unselected-v",
            },
            {
                "artifact_instance_identity": "artifact",
                "class_name": "Caller", "class_variant_identity": "caller-v",
            },
        ]
        reconciler.member_by_identity = {
            "caller-member": {
                "class_variant_identity": "caller-v", "class_name": "Caller",
            },
            "shadow-member": {
                "class_variant_identity": "unselected-v", "class_name": "Unselected",
            },
            "empty-caller-member": {
                "class_variant_identity": "caller-v",
            },
        }

        def provider_for(_realm, name):
            if name == "Caller":
                return resolved_provider(
                    "Caller", variant="caller-v", artifact="artifact",
                )
            if name == "Unselected":
                return resolved_provider(
                    "Unselected", variant="different-v", artifact="artifact",
                )
            if name == "Ambiguous":
                return {
                    "class_provider_status": "ambiguous",
                    "provider_binding_identity": "ambiguous-provider",
                }
            if name == "Missing":
                return {
                    "class_provider_status": "missing",
                    "provider_binding_identity": "missing-provider",
                }
            return resolved_provider(name, identity=f"provider-{name}")

        reconciler._provider = provider_for
        owner_names = {
            edge_row["symbolic_owner"] for edge_row in edges
            if edge_row["symbolic_owner"]
        } | {"java/lang/Object", "Component"}
        reconciler.definition_records = {
            ("app", name): definition(
                "failed", load_status="failed",
            ) if name == "Failed" else definition(identity=f"definition-{name}")
            for name in owner_names
            if name not in {"Ambiguous", "Missing", "[LComponent;", "[I"}
        }
        reconciler._type_resolution = lambda edge_row, _realm: {
            "type_resolution_identity": "type-resolution",
            "direct_edge_identity": edge_row["direct_edge_identity"],
        }
        reconciler._class_initialization_resolution = lambda edge_row, *_args: {
            "class_initialization_resolution_identity": "init-resolution",
            "direct_edge_identity": edge_row["direct_edge_identity"],
        }

        def member_for(_realm, owner, kind, _name, _descriptor):
            if owner == "NoMember":
                return None, provider_for("app", owner)
            flags = rr.ACC_FINAL if owner == "FinalMember" else 0
            member = {
                "member_identity": f"member-{owner}-{kind}",
                "class_name": owner,
                "access_flags": flags,
            }
            return member, provider_for("app", owner)

        reconciler._resolve_symbolic_member = member_for
        reconciler._member_accessible = lambda _caller, _realm, member, _provider: (
            member["class_name"] != "Illegal"
        )
        constraint_statuses = {
            "Deferred": "deferred_conflict",
            "ConstraintUnresolved": "unresolved",
        }
        reconciler._member_loading_constraints = (
            lambda _caller, _declaration, _types: ("resolved", [])
        )

        def loading_constraints(_caller, declaration, _types):
            owner = declaration.removeprefix("provider-realm-")
            return constraint_statuses.get(owner, "satisfied"), [{"owner": owner}]

        # Give each member provider a defining realm that identifies the owner.
        original_member_for = reconciler._resolve_symbolic_member

        def identified_member(*args):
            member, provider_row = original_member_for(*args)
            if provider_row is not None:
                provider_row = dict(provider_row)
                provider_row["selected_defining_loader_realm_identity"] = (
                    f"provider-realm-{args[1]}"
                )
            return member, provider_row

        reconciler._resolve_symbolic_member = identified_member
        reconciler._member_loading_constraints = loading_constraints
        reconciler._opcode_compatible = (
            lambda _edge, member: member["class_name"] != "Incompatible"
        )
        reconciler._class_info = lambda provider_row: (
            {"access_flags": rr.ACC_FINAL}
            if provider_row.get("class_name") == "FinalClass" else {}
        )
        reconciler._virtual_dispatch_targets = lambda _universe, owner, *_args: {
            "VirtualNone": (),
            "VirtualOne": ("target",),
            "VirtualMany": ("a", "b"),
        }.get(owner, ("fallback",))
        accumulator = CaptureAccumulator()
        reconciler._resolve_edges((('app', 'Caller'),), accumulator)
        records = {}
        for kind, record in accumulator.items:
            records[(kind, record["direct_edge_identity"])] = record
        self.assertIn(("type_resolution", "type"), records)
        self.assertIn(("class_initialization_resolution", "init"), records)
        self.assertIn(
            ("class_initialization_resolution", "init-empty-caller"), records,
        )
        self.assertEqual(
            records[("linkage_resolution", "constant")]["linkage_status"],
            "represented_by_bootstrap_handles",
        )
        self.assertEqual(
            records[("linkage_resolution", "constant-json")]["payload"],
            {"value": 1},
        )
        self.assertEqual(
            records[("dispatch_resolution", "zero-opcode")]["dispatch_status"],
            "exact",
        )
        self.assertEqual(
            records[("member_resolution", "ambiguous")]["member_resolution_status"],
            "ambiguous",
        )
        self.assertEqual(
            records[("member_resolution", "missing")]["member_resolution_status"],
            "no_class_definition",
        )
        self.assertEqual(
            records[("member_resolution", "failed")]["member_resolution_status"],
            "class_definition_failed",
        )
        self.assertEqual(
            records[("member_resolution", "no-member")]["member_resolution_status"],
            "no_such_member",
        )
        self.assertEqual(
            records[("linkage_resolution", "illegal")]["linkage_status"],
            "illegal_access",
        )
        self.assertEqual(
            records[("linkage_resolution", "deferred")]["linkage_status"],
            "loading_constraint_deferred_conflict",
        )
        self.assertEqual(
            records[("linkage_resolution", "constraint-unresolved")]["linkage_status"],
            "loading_constraint_unresolved",
        )
        self.assertEqual(
            records[("linkage_resolution", "incompatible")]["linkage_status"],
            "incompatible_class_change",
        )
        self.assertEqual(
            records[("dispatch_resolution", "field")]["dispatch_status"],
            "not_applicable",
        )
        self.assertEqual(
            records[("dispatch_resolution", "array")]["dispatch_status"],
            "exact",
        )
        self.assertEqual(
            records[("dispatch_resolution", "final-member")]["dispatch_status"],
            "exact",
        )
        self.assertEqual(
            records[("dispatch_resolution", "final-class")]["dispatch_status"],
            "exact",
        )
        self.assertEqual(
            records[("dispatch_resolution", "virtual-none")]["dispatch_status"],
            "no_concrete_implementation",
        )
        self.assertEqual(
            records[("dispatch_resolution", "virtual-one")]["dispatch_status"],
            "exact",
        )
        self.assertEqual(
            records[("dispatch_resolution", "virtual-many")]["dispatch_status"],
            "possible",
        )

        with patch.object(RuntimeReconciler, "DIRECT_EDGE_SCAN_ORDER", "invalid"):
            with self.assertRaises(rr.RuntimeReconciliationError) as raised:
                reconciler._resolve_edges((), CaptureAccumulator())
        self.assertEqual(
            raised.exception.reason_code, "RUNTIME_DIRECT_EDGE_SCAN_ORDER_INVALID",
        )

    def test_resolve_edges_partial_hierarchy_dispatch_matrix(self):
        def run(*, complete, closed, closure, gaps, targets):
            reconciler = blank_reconciler()
            reconciler.profile.complete = complete
            reconciler.profile.payload["runtime_class_closure_coverage_status"] = closure
            reconciler.capability = rr.RuntimeCapabilityPolicy(
                closed_world_dispatch=closed,
            )
            reconciler.coverage_gaps = set(gaps)
            reconciler.artifacts = {
                "artifact": {"loader_realm_identity": "app"},
            }
            reconciler.classes = [{
                "artifact_instance_identity": "artifact",
                "class_name": "Caller", "class_variant_identity": "caller-v",
            }]
            reconciler.member_by_identity = {
                "caller": {
                    "class_variant_identity": "caller-v", "class_name": "Caller",
                },
            }
            edge = {
                "direct_edge_identity": "edge",
                "caller_member_identity": "caller",
                "caller_artifact_instance_identity": "artifact",
                "instruction_index": 0, "bytecode_offset": 0,
                "edge_kind": "method", "opcode": 182,
                "symbolic_owner": "Owner", "symbolic_name": "m",
                "symbolic_descriptor": "()V", "edge_json": "{}",
            }
            reconciler.store = SimpleNamespace(
                connection=SimpleNamespace(execute=lambda _query: [edge]),
            )
            reconciler._provider = lambda _realm, name: resolved_provider(
                name,
                variant="caller-v" if name == "Caller" else "owner-v",
                artifact="artifact",
            )
            reconciler.definition_records = {("app", "Owner"): definition()}
            reconciler._resolve_symbolic_member = lambda *_args: (
                {"member_identity": "member", "class_name": "Owner", "access_flags": 0},
                resolved_provider("Owner"),
            )
            reconciler._member_accessible = lambda *_args: True
            reconciler._member_loading_constraints = lambda *_args: ("satisfied", [])
            reconciler._opcode_compatible = lambda *_args: True
            reconciler._class_info = lambda *_args: {"access_flags": 0}
            reconciler._virtual_dispatch_targets = lambda *_args: tuple(targets)
            accumulator = CaptureAccumulator()
            reconciler._resolve_edges((('app', 'Caller'),), accumulator)
            return next(
                record for kind, record in accumulator.items
                if kind == "dispatch_resolution"
            )

        cases = (
            (False, True, "complete", (), (), "unresolved"),
            (True, False, "complete", (), (), "unresolved"),
            (True, True, "partial", (), (), "unresolved"),
            (True, True, "complete", ("gap",), (), "unresolved"),
            (False, True, "complete", (), ("target",), "partial_possible_set"),
        )
        for complete, closed, closure, gaps, targets, expected in cases:
            with self.subTest(expected=expected, complete=complete, closed=closed):
                record = run(
                    complete=complete, closed=closed, closure=closure,
                    gaps=gaps, targets=targets,
                )
                self.assertEqual(record["dispatch_status"], expected)

    def test_compaction_universe_and_constructor_boundaries(self):
        reconciler = blank_reconciler()
        reconciler.provider_bindings = {
            ("app", "Full"): resolved_provider("Full"),
            ("app", "Sparse"): {
                "initiating_loader_realm_identity": "app",
                "class_name": "Sparse",
                "class_provider_status": "missing",
                "provider_binding_identity": "sparse-provider",
            },
        }
        reconciler.definition_records = {
            ("app", "Full"): {
                "initiating_loader_realm_identity": "app",
                "class_name": "Full",
                **definition(),
                "provider_binding_identity": "provider",
            },
            ("app", "Sparse"): {
                "initiating_loader_realm_identity": "app",
                "class_name": "Sparse",
                "class_definition_status": "unsupported",
                "class_definition_resolution_identity": "sparse-definition",
                "provider_binding_identity": "sparse-provider",
            },
        }
        reconciler._compact_persisted_runtime_records(set())
        self.assertIsInstance(
            reconciler.provider_bindings[("app", "Full")],
            rr._ProviderRuntimeRow,
        )
        self.assertIsInstance(
            reconciler.definition_records[("app", "Sparse")],
            rr._DefinitionRuntimeRow,
        )
        retained = blank_reconciler()
        original_provider = resolved_provider()
        original_definition = definition()
        retained.provider_bindings = {("app", "demo/Api"): original_provider}
        retained.definition_records = {("app", "demo/Api"): original_definition}
        retained._compact_persisted_runtime_records({
            "provider_binding", "class_definition",
        })
        self.assertIs(retained.provider_bindings[("app", "demo/Api")], original_provider)
        self.assertIs(retained.definition_records[("app", "demo/Api")], original_definition)

        class Connection:
            def execute(self, query, _parameters=()):
                if "SELECT DISTINCT edge.symbolic_owner" in query:
                    return [
                        {"symbolic_owner": "demo/Root"},
                        {"symbolic_owner": "[I"},
                    ]
                if "SELECT edge.edge_json" in query:
                    return [
                        {"edge_json": ""},
                        {"edge_json": json.dumps({
                            rr.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: ["Constraint"],
                        })},
                    ]
                return []

        universe = blank_reconciler()
        universe.store = SimpleNamespace(connection=Connection())
        universe.classes = [
            {"artifact_instance_identity": "artifact", "class_name": "demo/Root"},
            {"artifact_instance_identity": "artifact", "class_name": "module-info"},
            {"artifact_instance_identity": "outside", "class_name": "Outside"},
        ]
        universe.artifacts = {"artifact": {}}
        universe.additional_initial_classes = ("module-info", "Additional")
        universe.entrypoint_realms = ("app",)
        universe.realms = {"app": {}, "other": {}}
        provider_calls = []

        def provider_for(realm, name):
            provider_calls.append((realm, name))
            if name == "Missing":
                return {"class_provider_status": "missing", "class_name": name}
            return {
                **resolved_provider(name, realm=realm),
                "fact": (
                    {"super_name": "Dependency", "interfaces": ["", "Interface"]}
                    if name == "demo/Root" else None
                ),
            }

        universe._provider = provider_for
        universe._class_fact = lambda provider: provider.get("fact")
        result = universe._universe()
        self.assertIn(("app", "demo/Root"), result)
        self.assertIn(("other", "Constraint"), result)
        self.assertNotIn(("app", "module-info"), result)
        self.assertTrue(universe.platform.ensured)

        class EmptyConnection:
            def execute(self, _query):
                return []

        class Store:
            def __init__(self, artifacts=(), resources=()):
                self.connection = EmptyConnection()
                self.artifacts = list(artifacts)
                self.resources = list(resources)

            def rows(self, table, **_kwargs):
                return self.artifacts if table == "artifact_instances" else self.resources

        required = rr.RuntimeProfile.REQUIRED_FIELDS
        payload = {
            "runtime_platform_image_identity": "platform-id",
            "target_jvm": {"major": 17},
            "loader_topology": {
                "coverage_status": "complete",
                "entrypoint_realms": ["app"],
                "realms": [
                    {"identity": "platform", "kind": "platform"},
                    {"identity": "app", "kind": "application", "parent": "platform"},
                ],
            },
            "field_coverage": {**{field: "known" for field in required}, "target_os": "unknown"},
            "resource_selection_coverage_status": "partial",
        }
        artifact_row = {
            "artifact_instance_identity": "artifact",
            "loader_realm_identity": "app",
            "runtime_classpath_index": 0,
            "container_loader_policy_version": "flat-parent-first-v1",
            "coverage_status": "partial",
        }
        resource = {
            "artifact_instance_identity": "artifact",
            "resource_name": "resource",
            "resource_category": "unknown",
            "physical_entry_identity": "resource-entry",
        }
        outside_resource = {
            **resource,
            "artifact_instance_identity": "outside",
            "physical_entry_identity": "outside-entry",
        }
        profile = SimpleNamespace(payload=payload, identity="profile", complete=False)
        constructed = RuntimeReconciler(
            Store((artifact_row,), (resource, outside_resource)), profile, FakePlatform(),
            analysis_context_identity="context",
            capability_policy=rr.RuntimeCapabilityPolicy(),
            additional_initial_classes=("", "Extra", "Extra"),
        )
        self.assertEqual(constructed.additional_initial_classes, ("Extra",))
        self.assertIn("runtime_profile_field_unknown:target_os", constructed.coverage_gaps)
        self.assertIn("resource_selection_scope_incomplete", constructed.coverage_gaps)
        self.assertIn("artifact_fact_coverage_incomplete:artifact", constructed.coverage_gaps)

        all_unknown_coverage = {
            **payload,
            "field_coverage": {field: "unknown" for field in required},
        }
        missing_coverage = RuntimeReconciler(
            Store(),
            SimpleNamespace(
                payload=all_unknown_coverage,
                identity="profile-with-unknown-field-coverage",
                complete=False,
            ),
            FakePlatform(),
            analysis_context_identity="context",
        )
        self.assertTrue(all(
            f"runtime_profile_field_unknown:{field}" in missing_coverage.coverage_gaps
            for field in required
        ))

        for context, profile_payload, expected in (
            ("", payload, "RUNTIME_RECONCILIATION_CONTEXT_MISSING"),
            ("context", {**payload, "runtime_platform_image_identity": "other"}, "RUNTIME_PLATFORM_IMAGE_IDENTITY_MISMATCH"),
            ("context", {**payload, "target_jvm": "invalid"}, "RUNTIME_TARGET_JVM_PLATFORM_MISMATCH"),
            ("context", {**payload, "target_jvm": {}}, "RUNTIME_TARGET_JVM_PLATFORM_MISMATCH"),
        ):
            with self.subTest(expected=expected), self.assertRaises(
                rr.RuntimeReconciliationError
            ) as raised:
                RuntimeReconciler(
                    Store(), SimpleNamespace(
                        payload=profile_payload, identity="profile", complete=False,
                    ), FakePlatform(), analysis_context_identity=context,
                )
            self.assertEqual(raised.exception.reason_code, expected)

    def test_reconcile_transaction_short_circuits_and_result_aggregation(self):
        class Connection:
            def __init__(self, in_transaction):
                self.in_transaction = in_transaction
                self.begins = 0
                self.commits = 0
                self.rollbacks = 0

            def execute(self, statement):
                self.assert_begin(statement)
                self.begins += 1
                self.in_transaction = True

            @staticmethod
            def assert_begin(statement):
                if statement != "BEGIN":
                    raise AssertionError(statement)

            def commit(self):
                self.commits += 1
                self.in_transaction = False

            def rollback(self):
                self.rollbacks += 1
                self.in_transaction = False

        preexisting = blank_reconciler()
        preexisting_connection = Connection(True)
        preexisting.store = SimpleNamespace(connection=preexisting_connection)

        def fail_without_ownership(**_kwargs):
            raise RuntimeError("preexisting transaction failure")

        preexisting._reconcile = fail_without_ownership
        with self.assertRaisesRegex(RuntimeError, "preexisting"):
            preexisting.reconcile()
        self.assertEqual(preexisting_connection.begins, 0)
        self.assertEqual(preexisting_connection.rollbacks, 0)

        ended = blank_reconciler()
        ended_connection = Connection(False)
        ended.store = SimpleNamespace(connection=ended_connection)

        def fail_after_external_end(**_kwargs):
            ended_connection.in_transaction = False
            raise RuntimeError("transaction already ended")

        ended._reconcile = fail_after_external_end
        with self.assertRaisesRegex(RuntimeError, "already ended"):
            ended.reconcile()
        self.assertEqual(ended_connection.begins, 1)
        self.assertEqual(ended_connection.rollbacks, 0)

        class DummyAccumulator:
            def __init__(self, _store, _context, _retained):
                self.records = {
                    kind: [] for kind in rr._RECONCILIATION_RECORD_FIELDS
                }
                self.identities = {
                    kind: [] for kind in rr._RECONCILIATION_RECORD_FIELDS
                }
                self.flushed = False

            def add(self, kind, record):
                identity_key = rr._RECONCILIATION_RECORD_FIELDS[kind][1]
                self.records[kind].append(record)
                self.identities[kind].append(record[identity_key])

            def flush(self):
                self.flushed = True

            def canonical_subject_identities(self, kind):
                return self.identities[kind]

        aggregate = blank_reconciler()
        aggregate.store = SimpleNamespace()
        aggregate.coverage_gaps = {"objective-gap"}
        aggregate._universe = lambda: ()
        aggregate._compact_persisted_runtime_records = lambda _kinds: None
        aggregate._build_definitions = lambda _universe, _accumulator: None
        aggregate._resolve_edges = lambda _universe, _accumulator: None
        aggregate._resource_selections = lambda: [{
            "resource_selection_status": "resolved",
            "resource_selection_identity": "ab" * 32,
        }]
        with patch.object(rr, "_ReconciliationAccumulator", DummyAccumulator):
            result = aggregate._reconcile(retain_record_kinds=())
        self.assertEqual(result.coverage_status, "partial")
        self.assertEqual(result.coverage_gaps, ("objective-gap",))
        self.assertEqual(len(result.resource_selections), 1)


if __name__ == "__main__":
    unittest.main()
