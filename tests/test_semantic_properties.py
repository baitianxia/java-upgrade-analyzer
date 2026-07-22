import random
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import confidence_weighted_tracer as tracer  # noqa: E402
from signature_utils import (  # noqa: E402
    canonical_api_identity,
    normalize_signature_for_identity,
    normalize_signature_for_lookup,
    signatures_match_identity,
)
from step5_evidence_model import (  # noqa: E402
    EvidenceFailure,
    ModuleScope,
    ReachabilityPath,
    decide_analysis,
)


class SemanticPropertyTest(unittest.TestCase):
    """Deterministic generated/metamorphic checks for core conclusion invariants."""

    def test_signature_normalization_is_idempotent_across_generated_spellings(self):
        rng = random.Random(20260722)
        bases = ["String", "java.lang.String", "com.acme.Value", "int", "long"]
        for _index in range(250):
            count = rng.randrange(0, 5)
            params = []
            for _ in range(count):
                item = rng.choice(bases)
                if item not in {"int", "long"} and rng.choice((True, False)):
                    item += "<java.lang.String>"
                if rng.randrange(4) == 0:
                    item += "..."
                params.append(item)
            signature = "( " + " , ".join(params) + " )"
            identity = normalize_signature_for_identity(signature)
            lookup = normalize_signature_for_lookup(signature)
            with self.subTest(signature=signature):
                self.assertEqual(normalize_signature_for_identity(identity), identity)
                self.assertEqual(normalize_signature_for_lookup(lookup), lookup)

    def test_canonical_identity_is_invariant_to_safe_source_bytecode_rewrites(self):
        rng = random.Random(1701)
        for index in range(100):
            arity = rng.randrange(0, 4)
            qualified = [f"com.acme.Type{index}_{slot}" for slot in range(arity)]
            simple = [item.rsplit(".", 1)[-1] for item in qualified]
            source = {
                "coord": " com.acme:api ",
                "api_name": "com.acme.Outer$Inner.call",
                "api_signature": "(" + ", ".join(qualified) + ")",
                "symbol_kind": "METHOD",
                "change_type": " removed ",
            }
            bytecode = {
                **source,
                "coord": "com.acme:api",
                "api_name": "com.acme.Outer.Inner.call",
                "api_signature": "(" + ",".join(qualified) + ")",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            with self.subTest(index=index):
                self.assertEqual(canonical_api_identity(source), canonical_api_identity(bytecode))
                for left, right in zip(qualified, simple):
                    self.assertTrue(signatures_match_identity(f"({left})", f"({right})"))

    def test_overload_compatibility_is_permutation_invariant_and_never_changes_arity(self):
        overloads = [
            "(java.lang.String)",
            "(java.lang.String, java.lang.Object)",
            "(int)",
            "(java.lang.String, java.lang.Object[])",
        ]
        rng = random.Random(911)
        expected = None
        for _index in range(80):
            shuffled = list(overloads)
            rng.shuffle(shuffled)
            observed = sorted(tracer.select_compatible_overload_signatures(
                "(java.lang.String, java.lang.Object)", shuffled, {}
            ))
            expected = observed if expected is None else expected
            self.assertEqual(observed, expected)
            self.assertNotIn("(java.lang.String)", observed)

    def test_path_detail_dedup_is_idempotent_for_duplicate_candidates(self):
        graph = type("Graph", (), {})()
        for count in (1, 2, 5, 20):
            candidate = {
                "path": [],
                "reason": "DEPTH_LIMIT_REACHED",
                "boundary": {"reason": "DEPTH_LIMIT_REACHED"},
                "confidence": 0.4,
                "cost": 5,
                "depth": 5,
                "budget_limit": 5,
                "truncated_target": "com.acme.Entry.run",
            }
            details = tracer.build_all_candidate_path_details(
                [], [dict(candidate) for _ in range(count)], [], graph
            )
            with self.subTest(count=count):
                self.assertEqual(len(details), 1)
                self.assertEqual(details[0]["path_status"], "uncertain")

    def test_conclusion_state_is_monotone_when_supporting_evidence_is_added(self):
        reachable = ReachabilityPath(
            path_text="App.run -> Legacy.call",
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=True,
            depth=1,
        )
        additions = [
            (),
            (ReachabilityPath(
                path_text="Dependency.bridge -> Legacy.call",
                entry_scope=ModuleScope.EXTERNAL_DEPENDENCY,
                complete=False,
            ),),
            (ReachabilityPath(
                path_text="App.other -> Legacy.call",
                entry_scope=ModuleScope.BUSINESS_CLASSES,
                complete=True,
                ambiguous=True,
            ),),
        ]
        for extra in additions:
            decision = decide_analysis((reachable, *extra), failures=(EvidenceFailure(
                stage="optional-source",
                reason_code="OPTIONAL_SOURCE_MISSING",
                blocking=False,
            ),))
            with self.subTest(extra=extra):
                self.assertEqual(decision.analysis_status, "reachable")
                self.assertIs(decision.is_reachable, True)

    def test_incomplete_evidence_never_promotes_to_a_negative_or_reachable_state(self):
        for complete_scan in (False,):
            for failures in ((), (EvidenceFailure(
                stage="bytecode",
                reason_code="BYTECODE_PARSE_FAILED",
                blocking=True,
            ),)):
                decision = decide_analysis((), failures=failures, complete_scan=complete_scan)
                with self.subTest(failures=failures):
                    self.assertEqual(decision.analysis_status, "not_analyzed")
                    self.assertIsNone(decision.is_reachable)

    def test_depth_budget_stops_at_every_generated_boundary(self):
        for maximum in range(1, 20):
            before = tracer.should_stop_tracing(maximum - 1, maximum, 1.0, None)
            at_limit = tracer.should_stop_tracing(maximum, maximum, 1.0, None)
            beyond = tracer.should_stop_tracing(maximum + 5, maximum, 1.0, None)
            with self.subTest(maximum=maximum):
                self.assertEqual(before, (False, None))
                self.assertEqual(at_limit, (True, "DEPTH_LIMIT_REACHED"))
                self.assertEqual(beyond, (True, "DEPTH_LIMIT_REACHED"))


if __name__ == "__main__":
    unittest.main()
