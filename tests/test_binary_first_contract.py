import sys
import json
import hashlib
import random
from pathlib import Path
import unittest
from unittest import mock


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_first_contract as contract  # noqa: E402


class BinaryFirstContractTest(unittest.TestCase):
    def test_support_and_performance_manifests_allow_only_validated_authority_scope(self):
        support_path = ROOT_DIR / "scripts" / "binary_first_support_manifest.json"
        performance_path = (
            ROOT_DIR / "tests" / "fixtures" / "binary_first" / "performance_gate.json"
        )
        support = json.loads(
            support_path.read_text(encoding="utf-8")
        )
        performance = json.loads(
            performance_path.read_text(encoding="utf-8")
        )

        self.assertEqual(tuple(support["phase_contract"]), contract.PHASE_ORDER)
        self.assertEqual(support["authority"], "binary_first_only_fail_closed")
        self.assertNotIn("engine_modes", support)
        self.assertTrue(
            support["runtime_loader_support_manifest"][
                "authoritative_runtime_effective_decisions_allowed"
            ]
        )
        self.assertTrue(
            support["oracle_support_manifest"][
                "production_binary_authority_switch_allowed"
            ]
        )
        self.assertFalse(performance["blocks_binary_authority_switch"])
        self.assertEqual(performance["status"], "passed")
        self.assertGreater(performance["thresholds"]["cold_end_to_end_seconds"], 0)
        self.assertGreater(performance["thresholds"]["warm_end_to_end_p95_seconds"], 0)
        self.assertGreater(performance["thresholds"]["warm_end_to_end_p50_seconds"], 0)
        self.assertGreater(
            performance["thresholds"]["full_pipeline_end_to_end_seconds"], 0
        )
        self.assertGreater(
            performance["thresholds"]["full_pipeline_peak_rss_bytes"], 0
        )
        self.assertGreater(
            performance["thresholds"][
                "changed_full_pipeline_end_to_end_seconds"
            ],
            0,
        )
        self.assertGreater(
            performance["thresholds"][
                "changed_full_pipeline_peak_rss_bytes"
            ],
            0,
        )
        self.assertGreater(
            performance["recorded_measurements"]["full_pipeline_probe"][
                "peak_rss_bytes"
            ],
            0,
        )
        self.assertEqual(
            performance["measurement_protocol"]["full_pipeline_probe"][
                "class_count"
            ],
            performance["accuracy_invariants"][
                "full_pipeline_expected_class_count"
            ],
        )
        changed_protocol = performance["measurement_protocol"][
            "changed_full_pipeline_probe"
        ]
        self.assertEqual(changed_protocol["changed_jar_count"], 1)
        self.assertEqual(changed_protocol["changed_class_count"], 250)
        self.assertEqual(
            performance["recorded_measurements"][
                "changed_full_pipeline_probe"
            ]["authoritative_member_change_kind_counts"],
            {"implementation_changed": 250},
        )
        self.assertEqual(
            hashlib.sha256(performance_path.read_bytes()).hexdigest(),
            support["performance_gate"]["sha256"],
        )

    def test_canonical_identity_is_order_independent_but_list_order_sensitive(self):
        first = contract.canonical_identity(
            "example", {"b": 2, "a": ["first", "second"]}, schema_version="1"
        )
        reordered_keys = contract.canonical_identity(
            "example", {"a": ["first", "second"], "b": 2}, schema_version="1"
        )
        reordered_list = contract.canonical_identity(
            "example", {"a": ["second", "first"], "b": 2}, schema_version="1"
        )

        self.assertEqual(first, reordered_keys)
        self.assertNotEqual(first, reordered_list)

    def test_artifact_content_identity_rejects_non_sha_input(self):
        for value in (None, "", "not-a-sha"):
            with self.subTest(value=value), self.assertRaises(
                contract.BinaryFirstContractError
            ) as error:
                contract.artifact_content_identity(value, 10)
            self.assertEqual(
                error.exception.reason_code, "ARTIFACT_CONTENT_SHA256_INVALID"
            )

    def test_canonical_identity_rejects_non_string_object_keys(self):
        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.canonical_identity(
                "example",
                {1: "would-collide-with-string-one", "1": "value"},
                schema_version="1",
            )

        self.assertEqual(error.exception.reason_code, "BINARY_IDENTITY_KEY_INVALID")

    def test_canonical_identity_rejects_non_finite_float(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                contract.canonical_identity(
                    "example", {"value": value}, schema_version="1"
                )

    def test_canonical_identity_supports_sets_and_rejects_unknown_values(self):
        first = contract.canonical_identity(
            "example", {"values": {"b", "a"}}, schema_version="1"
        )
        second = contract.canonical_identity(
            "example", {"values": {"a", "b"}}, schema_version="1"
        )
        self.assertEqual(first, second)
        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.canonical_identity(
                "example", {"value": object()}, schema_version="1"
            )
        self.assertEqual(
            error.exception.reason_code, "BINARY_IDENTITY_VALUE_UNSUPPORTED"
        )

    def test_streaming_canonical_identity_is_byte_equivalent(self):
        payloads = (
            {},
            [],
            {"unicode": "运行时✓", "escaped": "line\n\"quoted\"\\"},
            {
                "nested": [
                    {"z": None, "a": (True, False, 1, -2, 3.25)},
                    {"set": {"beta", "alpha"}},
                ],
            },
            {"numbers": [0, -0.0, 1.0e-12, 1.0e20]},
            {"large_buffer_boundary": "x" * (70 * 1024)},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertEqual(
                    "".join(contract._iter_canonical_json(payload)),
                    contract.canonical_payload_bytes(payload).decode("utf-8"),
                )
                self.assertEqual(
                    contract.canonical_identity(
                        "example", payload, schema_version="1"
                    ),
                    contract.canonical_identity_streaming(
                        "example", payload, schema_version="1"
                    ),
                )

        for payload in ({1: "invalid-key"}, {"value": object()}):
            with self.subTest(payload=payload), self.assertRaises(
                contract.BinaryFirstContractError
            ):
                contract.canonical_identity_streaming(
                    "example", payload, schema_version="1"
                )
            with self.subTest(payload=payload), self.assertRaises(
                contract.BinaryFirstContractError
            ):
                "".join(contract._iter_canonical_json(payload))
        with self.assertRaises(ValueError):
            contract.canonical_identity_streaming(
                "example", {"value": float("nan")}, schema_version="1"
            )

    def test_streaming_canonical_identity_randomized_byte_equivalence(self):
        random_source = random.Random(20260813)
        scalar_values = (
            None, False, True, 0, -1, 2**63, -0.0, 3.25, 1.0e-12,
            "", "ascii", "运行时✓", "line\n\"quoted\"\\", "😀", "\u0000",
        )

        def value(depth):
            if depth == 0:
                return random_source.choice(scalar_values)
            kind = random_source.randrange(5)
            if kind == 0:
                return random_source.choice(scalar_values)
            if kind == 1:
                return [value(depth - 1) for _ in range(random_source.randrange(5))]
            if kind == 2:
                return tuple(
                    value(depth - 1) for _ in range(random_source.randrange(5))
                )
            if kind == 3:
                return {
                    f"key-{index}-{random_source.randrange(1000)}": value(depth - 1)
                    for index in range(random_source.randrange(5))
                }
            return {
                random_source.choice(("alpha", "beta", "运行时", "😀"))
                for _ in range(random_source.randrange(5))
            }

        for index in range(500):
            payload = value(4)
            with self.subTest(index=index, payload=payload):
                self.assertEqual(
                    contract.canonical_identity(
                        "randomized-equivalence", payload, schema_version="1"
                    ),
                    contract.canonical_identity_streaming(
                        "randomized-equivalence", payload, schema_version="1"
                    ),
                )

    def test_native_json_identity_is_byte_equivalent_for_internal_trees(self):
        payloads = (
            None,
            {"text": "运行时✓", "escaped": "line\n\"quoted\"\\"},
            {"values": [None, False, True, 0, -1, -0.0, 3.25, 1.0e20]},
            {"nested": ({"b": 2, "a": 1}, ("x", "😀"))},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertEqual(
                    contract.canonical_identity(
                        "native-json", payload, schema_version="1"
                    ),
                    contract.canonical_identity_native_json(
                        "native-json", payload, schema_version="1"
                    ),
                )
        with self.assertRaises(ValueError):
            contract.canonical_identity_native_json(
                "native-json", {"value": float("nan")}, schema_version="1"
            )
        with self.assertRaises(TypeError):
            contract.canonical_identity_native_json(
                "native-json", {"value": {"unsupported"}}, schema_version="1"
            )

        with mock.patch.object(contract, "_NATIVE_JSON_C_ENCODER", None):
            self.assertEqual(
                contract.canonical_identity(
                    "native-json", payloads[1], schema_version="1"
                ),
                contract.canonical_identity_native_json(
                    "native-json", payloads[1], schema_version="1"
                ),
            )

    def test_canonical_identity_losslessly_encodes_unpaired_surrogates(self):
        raw_surrogate = json.loads('"\\ud800"')
        literal_escape = "\\ud800"
        payload = {"value": raw_surrogate}

        ordinary = contract.canonical_identity(
            "surrogate", payload, schema_version="1"
        )
        self.assertEqual(
            ordinary,
            contract.canonical_identity_native_json(
                "surrogate", payload, schema_version="1"
            ),
        )
        self.assertEqual(
            ordinary,
            contract.canonical_identity_streaming(
                "surrogate", payload, schema_version="1"
            ),
        )
        self.assertNotEqual(
            ordinary,
            contract.canonical_identity(
                "surrogate", {"value": literal_escape}, schema_version="1"
            ),
        )
        encoded = contract.surrogate_safe_json_bytes(
            {"value": raw_surrogate}, ensure_ascii=False
        )
        self.assertEqual(json.loads(encoded.decode("utf-8")), payload)

    def test_canonical_json_string_matches_frozen_encoder(self):
        values = (
            "",
            "plain",
            "line\n\"quoted\"\\",
            "运行时😀",
            json.loads('"\\ud800"'),
        )
        for value in values:
            with self.subTest(value=repr(value)):
                self.assertEqual(
                    contract.canonical_json_string(value),
                    contract.surrogate_safe_json_dumps(
                        value,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ),
                )
        with self.assertRaisesRegex(
            contract.BinaryFirstContractError,
            "canonical JSON string values must be native strings",
        ):
            contract.canonical_json_string(1)

    def test_jvm_text_transport_is_reversible_and_collision_free(self):
        raw_surrogate = json.loads('"\\ud800"')
        values = (
            raw_surrogate,
            "\\ud800",
            "~jua-utf16-v1~literal",
            "运行时😀",
        )
        transported = [contract.transport_jvm_text(value) for value in values]

        self.assertEqual(len(set(transported)), len(values))
        self.assertEqual(
            [contract.restore_jvm_text(value) for value in transported],
            list(values),
        )

    def test_jvm_transport_covers_empty_nested_and_mixed_container_trees(self):
        surrogate = json.loads('"\\ud800"')
        ordinary_values = (
            None,
            "plain",
            {},
            [],
            (),
            {"key": "value", 7: False},
            ["value", {"nested": ()}],
        )
        for value in ordinary_values:
            with self.subTest(value=value):
                self.assertFalse(contract._jvm_value_requires_transport(value))
                self.assertIs(contract.transport_jvm_value(value), value)

        value = {
            "surrogate-key-" + surrogate: "key-value",
            7: "non-string-key",
            "text": surrogate,
            "empty_dict": {},
            "empty_list": [],
            "empty_tuple": (),
            "list": [surrogate, "ordinary"],
            "tuple": ("ordinary", surrogate),
            "scalar": 3,
        }
        transported = contract.transport_jvm_value(value)
        self.assertIsNot(transported, value)
        self.assertEqual(transported[7], "non-string-key")
        self.assertEqual(transported["scalar"], 3)
        self.assertEqual(
            contract.restore_jvm_text(transported["text"]), surrogate
        )
        transported_key = next(
            key for key in transported if isinstance(key, str) and "surrogate-key" not in key
        )
        self.assertEqual(
            contract.restore_jvm_text(transported_key), "surrogate-key-" + surrogate
        )
        self.assertTrue(contract._jvm_value_requires_transport([{}, surrogate]))
        self.assertTrue(contract._jvm_value_requires_transport((surrogate,)))

    def test_jvm_transport_rejects_malformed_base64_and_odd_utf16_length(self):
        malformed = (
            contract.JVM_TEXT_TRANSPORT_PREFIX + "!",
            contract.JVM_TEXT_TRANSPORT_PREFIX + "YQ==",
            contract.JVM_TEXT_TRANSPORT_PREFIX + json.loads('"\\ud800"'),
        )
        for value in malformed:
            with self.subTest(value=repr(value)), self.assertRaises(
                contract.BinaryFirstContractError
            ) as raised:
                contract.restore_jvm_text(value)
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_JVM_TEXT_TRANSPORT_INVALID",
            )

    def test_surrogate_escape_handles_empty_plain_and_mixed_text_directly(self):
        surrogate = json.loads('"\\ud800"')
        self.assertEqual(contract._escape_json_surrogates(""), "")
        self.assertEqual(contract._escape_json_surrogates("plain"), "plain")
        self.assertEqual(
            contract._escape_json_surrogates("a" + surrogate + "b"),
            "a\\ud800b",
        )

    def test_identity_entrypoints_reject_each_missing_namespace_component(self):
        for identity in (
            contract.canonical_identity,
            contract.canonical_identity_native_json,
            contract.canonical_identity_streaming,
        ):
            cases = (
                (None, "1"),
                ("", "1"),
                ("   ", "1"),
                ("namespace", None),
                ("namespace", ""),
                ("namespace", "   "),
            )
            for namespace, schema_version in cases:
                with self.subTest(
                    identity=identity.__name__,
                    namespace=namespace,
                    schema_version=schema_version,
                ), self.assertRaises(contract.BinaryFirstContractError) as raised:
                    identity(
                        namespace,
                        {"payload": True},
                        schema_version=schema_version,
                    )
                self.assertEqual(
                    raised.exception.reason_code,
                    "BINARY_IDENTITY_NAMESPACE_MISSING",
                )

    def test_streaming_factory_and_digest_empty_buffer_boundaries(self):
        with self.assertRaises(contract.BinaryFirstContractError) as raised:
            contract.StreamingCanonicalSequence(None)
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_STREAMING_SEQUENCE_FACTORY_INVALID",
        )

        # One scalar chunk larger than the flush threshold leaves no tail for
        # the final flush while preserving byte-for-byte identity equivalence.
        payload = "x" * contract._STREAMING_DIGEST_BUFFER_CHARS
        self.assertEqual(
            contract.canonical_identity_streaming(
                "flush-boundary", payload, schema_version="1"
            ),
            contract.canonical_identity(
                "flush-boundary", payload, schema_version="1"
            ),
        )
        digest = hashlib.sha256()
        contract._update_canonical_digest(digest, payload)
        self.assertEqual(
            digest.digest(),
            hashlib.sha256(contract.canonical_payload_bytes(payload)).digest(),
        )

    def test_contract_error_uses_stable_default_reason_for_empty_codes(self):
        for value in (None, "", 0):
            with self.subTest(value=value):
                error = contract.BinaryFirstContractError(value, "message")
                self.assertEqual(
                    error.reason_code, "BINARY_FIRST_CONTRACT_VIOLATION"
                )

    def test_native_type_fast_paths_preserve_the_frozen_identity(self):
        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        class IntSubclass(int):
            pass

        payload = DictSubclass({
            "z": ListSubclass([
                IntSubclass(7), None, True, {"values": {"beta", "alpha"}},
            ]),
            "a": {"unicode": "运行时✓", "tuple": ("x", -2, 3.25)},
        })
        expected = (
            "eef9286e35d4dcd144f938c71c5a4f6a"
            "c31c8a6540926bda9e47759b6eb92dc8"
        )

        self.assertEqual(
            contract.canonical_identity(
                "fast-path-regression", payload, schema_version="1"
            ),
            expected,
        )
        self.assertEqual(
            contract.canonical_identity_streaming(
                "fast-path-regression", payload, schema_version="1"
            ),
            expected,
        )
        self.assertEqual(
            "".join(contract._iter_canonical_json(payload)),
            contract.canonical_payload_bytes(payload).decode("utf-8"),
        )

    def test_container_subclass_fallbacks_match_and_reject_invalid_keys(self):
        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        class SetSubclass(set):
            pass

        payloads = (
            ListSubclass(["native", 1, True]),
            SetSubclass({"beta", "alpha"}),
        )
        for payload in payloads:
            with self.subTest(container=type(payload).__name__):
                self.assertEqual(
                    "".join(contract._iter_canonical_json(payload)),
                    contract.canonical_payload_bytes(payload).decode("utf-8"),
                )
                self.assertEqual(
                    contract.canonical_identity(
                        "container-subclass", payload, schema_version="1"
                    ),
                    contract.canonical_identity_streaming(
                        "container-subclass", payload, schema_version="1"
                    ),
                )

        invalid = DictSubclass({1: "non-string-key"})
        for identity in (
            contract.canonical_identity,
            contract.canonical_identity_streaming,
        ):
            with self.subTest(identity=identity.__name__), self.assertRaises(
                contract.BinaryFirstContractError
            ) as error:
                identity("container-subclass", invalid, schema_version="1")
            self.assertEqual(
                error.exception.reason_code, "BINARY_IDENTITY_KEY_INVALID"
            )
        with self.assertRaises(contract.BinaryFirstContractError) as error:
            "".join(contract._iter_canonical_json(invalid))
        self.assertEqual(error.exception.reason_code, "BINARY_IDENTITY_KEY_INVALID")

    def test_streaming_sequence_is_repeatable_and_byte_equivalent(self):
        values = ["first", "运行时", "third"]
        sequence = contract.StreamingCanonicalSequence(lambda: iter(values))
        payload = {"values": sequence}

        expected = contract.canonical_identity(
            "example", {"values": values}, schema_version="1"
        )
        self.assertEqual(
            contract.canonical_identity_streaming(
                "example", payload, schema_version="1"
            ),
            expected,
        )
        self.assertEqual(
            "".join(contract._iter_canonical_json(sequence)),
            contract.canonical_payload_bytes(values).decode("utf-8"),
        )
        self.assertEqual(
            contract.canonical_identity_streaming(
                "example", payload, schema_version="1"
            ),
            expected,
        )
        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.canonical_identity("example", payload, schema_version="1")
        self.assertEqual(
            error.exception.reason_code, "BINARY_IDENTITY_VALUE_UNSUPPORTED"
        )

    def test_artifact_content_identity_rejects_invalid_lengths(self):
        digest = "a" * 64
        for value in (None, "not-an-int", "1", 1.0, True, -1):
            with self.subTest(value=value), self.assertRaises(
                contract.BinaryFirstContractError
            ) as error:
                contract.artifact_content_identity(digest, value)
            self.assertEqual(
                error.exception.reason_code, "ARTIFACT_CONTENT_LENGTH_INVALID"
            )

        self.assertEqual(
            contract.artifact_content_identity("A" * 64, 0),
            contract.artifact_content_identity("a" * 64, 0),
        )

    def test_identity_builders_reject_every_independently_missing_field(self):
        context_cases = (
            (None, "scope"),
            ("", "scope"),
            ("   ", "scope"),
            ("runtime", None),
            ("runtime", ""),
            ("runtime", "   "),
        )
        for runtime, scope in context_cases:
            with self.subTest(kind="context", runtime=runtime, scope=scope), \
                    self.assertRaises(contract.BinaryFirstContractError) as raised:
                contract.analysis_context_identity(runtime, scope)
            self.assertEqual(
                raised.exception.reason_code, "ANALYSIS_CONTEXT_INPUT_MISSING"
            )

        for observed, context in (
            (None, "context"),
            ("", "context"),
            ("   ", "context"),
            ("observed", None),
            ("observed", ""),
            ("observed", "   "),
        ):
            with self.subTest(kind="disposition", observed=observed, context=context), \
                    self.assertRaises(contract.BinaryFirstContractError) as raised:
                contract.disposition_obligation_identity(observed, context)
            self.assertEqual(
                raised.exception.reason_code,
                "DISPOSITION_OBLIGATION_INPUT_MISSING",
            )

        projection_fields = ["rule", "target", "family"]
        for index in range(len(projection_fields)):
            values = list(projection_fields)
            values[index] = None
            with self.subTest(kind="projection", missing=index), self.assertRaises(
                contract.BinaryFirstContractError
            ) as raised:
                contract.projection_obligation_key(*values)
            self.assertEqual(
                raised.exception.reason_code,
                "PROJECTION_OBLIGATION_INPUT_MISSING",
            )
        self.assertEqual(
            len(contract.projection_obligation_key(*projection_fields)), 64
        )

        observed_fields = {
            "delta_source_kind": "artifact_local",
            "comparison_or_runtime_scope": {"runtime": "pair"},
            "fact_or_mechanism_scope": {"member": "run()V"},
            "base_fingerprint": "base",
            "current_fingerprint": "current",
        }
        for field in tuple(observed_fields):
            values = dict(observed_fields)
            values[field] = {} if field.endswith("scope") else None
            with self.subTest(kind="observed", missing=field), self.assertRaises(
                contract.BinaryFirstContractError
            ) as raised:
                contract.observed_delta_identity(**values)
            self.assertEqual(
                raised.exception.reason_code, "OBSERVED_DELTA_INPUT_MISSING"
            )

    def test_observed_delta_is_shared_across_analysis_scopes(self):
        observed = contract.observed_delta_identity(
            delta_source_kind="artifact_local",
            comparison_or_runtime_scope={"runtime_comparison": "pair-1"},
            fact_or_mechanism_scope={"member": "com/acme/Api.run()V"},
            base_fingerprint="base-ir",
            current_fingerprint="current-ir",
        )
        first_context = contract.analysis_context_identity("pair-1", "scope-a")
        second_context = contract.analysis_context_identity("pair-1", "scope-b")

        self.assertNotEqual(
            contract.disposition_obligation_identity(observed, first_context),
            contract.disposition_obligation_identity(observed, second_context),
        )

    def test_contract_exposes_no_engine_selection_or_fallback_api(self):
        self.assertFalse(hasattr(contract, "ENGINE_MODES"))
        self.assertFalse(hasattr(contract, "IMPLEMENTED_ENGINE_MODES"))
        self.assertFalse(hasattr(contract, "require_implemented_engine_mode"))

    def test_reachable_truth_table_preserves_static_reachability(self):
        result = contract.derive_formal_result_state("reachable")

        self.assertEqual(result["analysis_status"], "reachable")
        self.assertTrue(result["is_reachable"])
        self.assertEqual(result["impact_conclusion"], "probable_impact")
        self.assertEqual(result["runtime_verification_status"], "required_not_executed")
        self.assertFalse(result["runtime_verification_executed_by_system"])
        self.assertEqual(result["runtime_verification_evidence"], [])
        self.assertEqual(result["best_path_certainty"], "exact_or_proven")
        self.assertTrue(contract.validate_formal_result_state(result))

    def test_reachable_truth_table_preserves_additional_possible_paths(self):
        result = contract.derive_formal_result_state(
            "reachable",
            possible_path_exists=True,
        )

        self.assertTrue(result["exact_path_exists"])
        self.assertTrue(result["possible_path_exists"])
        self.assertEqual(result["reachability_status"], "reachable")
        self.assertEqual(result["best_path_certainty"], "exact_or_proven")
        self.assertTrue(contract.validate_formal_result_state(result))

    def test_uncertain_truth_table_requires_a_complete_possible_path(self):
        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.derive_formal_result_state(
                "uncertain",
                possible_path_exists=False,
            )

        self.assertEqual(
            error.exception.reason_code,
            "FORMAL_POSSIBLE_PATH_STATE_INVALID",
        )

    def test_uncertain_truth_table_cannot_claim_probable_impact(self):
        result = contract.derive_formal_result_state("uncertain")
        result["impact_conclusion"] = "probable_impact"

        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.validate_formal_result_state(result)

        self.assertEqual(error.exception.reason_code, "FORMAL_STATE_TRUTH_TABLE_VIOLATION")

    def test_formal_truth_table_rejects_invalid_status_certainty_and_possible_path(self):
        cases = (
            ((None,), {}, "FORMAL_REACHABILITY_STATUS_INVALID"),
            (("",), {}, "FORMAL_REACHABILITY_STATUS_INVALID"),
            (("unknown",), {}, "FORMAL_REACHABILITY_STATUS_INVALID"),
            (("reachable",), {"best_path_certainty": "possible"},
             "FORMAL_BEST_PATH_CERTAINTY_INVALID"),
            (("not_found_in_static_analysis",), {"possible_path_exists": True},
             "FORMAL_POSSIBLE_PATH_STATE_INVALID"),
        )
        for args, kwargs, reason in cases:
            with self.subTest(reason=reason), self.assertRaises(
                contract.BinaryFirstContractError
            ) as error:
                contract.derive_formal_result_state(*args, **kwargs)
            self.assertEqual(error.exception.reason_code, reason)
        self.assertFalse(contract.derive_formal_result_state(
            "not_found_in_static_analysis"
        )["possible_path_exists"])

        self.assertFalse(contract.derive_formal_result_state(
            "not_analyzed"
        )["possible_path_exists"])

    def test_formal_validation_requires_confirmed_change_fact(self):
        for payload in (None, {}, {"change_fact_status": "candidate"}):
            with self.subTest(payload=payload), self.assertRaises(
                contract.BinaryFirstContractError
            ) as error:
                contract.validate_formal_result_state(payload)
            self.assertEqual(
                error.exception.reason_code, "FORMAL_CHANGE_FACT_NOT_CONFIRMED"
            )

    def test_static_v2_rejects_confirmed_impact(self):
        result = contract.derive_formal_result_state("reachable")
        result["decision_bucket"] = "confirmed_impact"

        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.validate_formal_result_state(result)

        self.assertEqual(error.exception.reason_code, "FORMAL_STATIC_V2_FORBIDDEN_STATE")

    def test_formal_validation_rejects_each_empty_observed_state_field(self):
        for field in (
            "impact_conclusion",
            "decision_bucket",
            "runtime_verification_status",
        ):
            result = contract.derive_formal_result_state("reachable")
            result[field] = None
            with self.subTest(field=field), self.assertRaises(
                contract.BinaryFirstContractError
            ) as raised:
                contract.validate_formal_result_state(result)
            self.assertEqual(
                raised.exception.reason_code,
                "FORMAL_STATE_TRUTH_TABLE_VIOLATION",
            )

    def test_projection_assessment_requires_obligation_conservation(self):
        self.assertTrue(contract.validate_projection_assessment({
            "analysis_projection_status": "targetable",
            "projection_coverage_status": "partial",
            "target_count": 1,
            "projection_obligation_count": 2,
            "projection_count": 2,
            "partial_scopes": ["reflection-consumers"],
        }))
        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.validate_projection_assessment({
                "analysis_projection_status": "targetable",
                "projection_coverage_status": "complete",
                "target_count": 1,
                "projection_obligation_count": 2,
                "projection_count": 1,
            })

        self.assertEqual(error.exception.reason_code, "PROJECTION_OBLIGATION_COUNT_MISMATCH")

    def test_projection_assessment_exercises_all_invalid_contract_branches(self):
        self.assertTrue(contract.validate_projection_assessment({
            "analysis_projection_status": "unsupported",
            "projection_coverage_status": "unsupported",
        }))
        invalid = (
            ({"analysis_projection_status": "unsupported",
              "projection_coverage_status": "complete"},
             "UNSUPPORTED_PROJECTION_ASSESSMENT_INVALID"),
            ({"analysis_projection_status": "targetable",
              "projection_coverage_status": "unsupported",
              "target_count": 1, "projection_obligation_count": 1,
              "projection_count": 1}, "TARGETABLE_PROJECTION_COVERAGE_INVALID"),
            ({"analysis_projection_status": "targetable",
              "projection_coverage_status": "complete"},
             "TARGETABLE_PROJECTION_OBLIGATION_MISSING"),
            ({"analysis_projection_status": "targetable",
              "projection_coverage_status": "complete", "target_count": 1,
              "projection_obligation_count": 1, "projection_count": 1,
              "partial_scopes": ["gap"]}, "COMPLETE_PROJECTION_HAS_PARTIAL_SCOPE"),
            ({"analysis_projection_status": "targetable",
              "projection_coverage_status": "partial", "target_count": 1,
              "projection_obligation_count": 1, "projection_count": 1},
             "PARTIAL_PROJECTION_SCOPE_MISSING"),
            ({"analysis_projection_status": "other"},
             "PROJECTION_ASSESSMENT_STATUS_INVALID"),
        )
        for payload, reason in invalid:
            with self.subTest(reason=reason), self.assertRaises(
                contract.BinaryFirstContractError
            ) as error:
                contract.validate_projection_assessment(payload)
            self.assertEqual(error.exception.reason_code, reason)

    def test_projection_assessment_covers_short_circuit_and_valid_boundaries(self):
        self.assertTrue(contract.validate_projection_assessment({
            "analysis_projection_status": "targetable",
            "projection_coverage_status": "complete",
            "target_count": 1,
            "projection_obligation_count": 1,
            "projection_count": 1,
            "partial_scopes": [],
        }))
        self.assertTrue(contract.validate_projection_assessment({
            "analysis_projection_status": "targetable",
            "projection_coverage_status": "partial",
            "target_count": 1,
            "projection_obligation_count": 1,
            "projection_count": 1,
            "partial_scopes": ["scope"],
        }))
        invalid = (
            (None, "PROJECTION_ASSESSMENT_STATUS_INVALID"),
            ({}, "PROJECTION_ASSESSMENT_STATUS_INVALID"),
            ({
                "analysis_projection_status": "unsupported",
                "projection_coverage_status": "unsupported",
                "target_count": 1,
            }, "UNSUPPORTED_PROJECTION_ASSESSMENT_INVALID"),
            ({
                "analysis_projection_status": "targetable",
                "projection_coverage_status": "complete",
                "target_count": 1,
                "projection_obligation_count": 0,
            }, "TARGETABLE_PROJECTION_OBLIGATION_MISSING"),
        )
        for payload, reason in invalid:
            with self.subTest(payload=payload), self.assertRaises(
                contract.BinaryFirstContractError
            ) as raised:
                contract.validate_projection_assessment(payload)
            self.assertEqual(raised.exception.reason_code, reason)

    def test_possible_layer_controls_compatibility_completeness(self):
        self.assertTrue(contract.derive_path_set_complete(
            exact_path_set_complete=True,
            possible_path_layer_applicable=False,
            possible_path_set_complete=False,
        ))
        self.assertFalse(contract.derive_path_set_complete(
            exact_path_set_complete=True,
            possible_path_layer_applicable=True,
            possible_path_set_complete=False,
        ))
        self.assertFalse(contract.derive_path_set_complete(
            exact_path_set_complete=False,
            possible_path_layer_applicable=False,
            possible_path_set_complete=True,
        ))
        self.assertTrue(contract.derive_path_set_complete(
            exact_path_set_complete=True,
            possible_path_layer_applicable=True,
            possible_path_set_complete=True,
        ))

    def test_phase_manifest_is_one_way_and_digest_bound(self):
        result = contract.validate_phase_manifest([
            {
                "phase": "step4a_artifact_local_diff",
                "status": "completed",
                "input_digest": "input-a",
                "output_digest": "output-a",
            },
            {
                "phase": "step5a_target_independent_reconciliation",
                "status": "pending",
            },
        ])
        self.assertEqual(result["completed_phase_count"], 1)
        self.assertEqual(result["next_phase"], "step5a_target_independent_reconciliation")

        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.validate_phase_manifest([{
                "phase": "step5a_target_independent_reconciliation",
                "status": "completed",
                "input_digest": "input-b",
                "output_digest": "output-b",
            }])
        self.assertEqual(error.exception.reason_code, "BINARY_PHASE_ORDER_INVALID")

    def test_phase_manifest_rejects_duplicate_status_digest_and_terminal_tail(self):
        invalid = (
            ([{"phase": "step4a_artifact_local_diff", "status": "completed",
               "input_digest": "in", "output_digest": "out"},
              {"phase": "step4a_artifact_local_diff", "status": "pending"}],
             "BINARY_PHASE_MANIFEST_INVALID"),
            ([{"phase": "step4a_artifact_local_diff", "status": "unknown"}],
             "BINARY_PHASE_STATUS_INVALID"),
            ([{"phase": "step4a_artifact_local_diff", "status": "completed"}],
             "BINARY_PHASE_DIGEST_MISSING"),
            ([{"phase": "step4a_artifact_local_diff", "status": "pending"},
              {"phase": "step5a_target_independent_reconciliation",
               "status": "pending"}], "BINARY_PHASE_AFTER_TERMINAL_STATE"),
        )
        for records, reason in invalid:
            with self.subTest(reason=reason), self.assertRaises(
                contract.BinaryFirstContractError
            ) as error:
                contract.validate_phase_manifest(records)
            self.assertEqual(error.exception.reason_code, reason)

    def test_phase_manifest_covers_empty_fields_output_digest_and_full_completion(self):
        self.assertEqual(
            contract.validate_phase_manifest(None),
            {"completed_phase_count": 0, "next_phase": contract.PHASE_ORDER[0]},
        )
        invalid = (
            ([None], "BINARY_PHASE_MANIFEST_INVALID"),
            ([{"phase": "", "status": "pending"}],
             "BINARY_PHASE_MANIFEST_INVALID"),
            ([{"phase": contract.PHASE_ORDER[0], "status": ""}],
             "BINARY_PHASE_STATUS_INVALID"),
            ([{
                "phase": contract.PHASE_ORDER[0],
                "status": "completed",
                "input_digest": "input",
                "output_digest": None,
            }], "BINARY_PHASE_DIGEST_MISSING"),
        )
        for records, reason in invalid:
            with self.subTest(reason=reason), self.assertRaises(
                contract.BinaryFirstContractError
            ) as raised:
                contract.validate_phase_manifest(records)
            self.assertEqual(raised.exception.reason_code, reason)

        complete = [
            {
                "phase": phase,
                "status": "completed",
                "input_digest": f"input-{index}",
                "output_digest": f"output-{index}",
            }
            for index, phase in enumerate(contract.PHASE_ORDER)
        ]
        self.assertEqual(
            contract.validate_phase_manifest(complete),
            {"completed_phase_count": len(contract.PHASE_ORDER), "next_phase": ""},
        )


if __name__ == "__main__":
    unittest.main()
