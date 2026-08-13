import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.blackbox.oracles.reference_query_oracle import expected_chains


ROOT = Path(__file__).resolve().parents[2]
TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "workflow_blackbox"
    / "query_public_contract_v1.json"
).read_text(encoding="utf-8"))


METHODS = {
    name: {
        "symbol_id": name,
        "qualified_key": qualified,
        "simple_key": "method:run",
        "class_fqcn": qualified.rsplit(".", 2)[0],
        "method_name": "run",
        "declared_signature": "()",
        "declared_qualified_key": qualified,
        "owner_type": "business",
        "owner_coord": "BUSINESS",
        "module": "app",
        "file": f"{name}.java",
        "line": 1,
        "is_test": False,
    }
    for name, qualified in (
        ("a", "app.A.run()"),
        ("b", "app.B.run()"),
        ("dto", "app.Dto.run()"),
        ("fuzzy", "app.Fuzzy.run()"),
    )
}


def edge(caller: str, target: str) -> dict:
    return {
        "caller_symbol_id": caller,
        "caller_qualified_key": METHODS[caller]["qualified_key"],
        "callee_key": target,
        "callee_simple_key": "method:changed",
        "evidence_type": "closed_fixture",
        "confidence": "high",
        "file": METHODS[caller]["file"],
        "line": 1,
        "owner_type": "business",
        "owner_coord": "BUSINESS",
        "module": "app",
        "is_test": False,
        "callee_fqcn_complete": True,
        "callee_signature_complete": True,
        "callee_resolution_note": "",
    }


GRAPH_EDGES = (
    {
        "caller": "a",
        "target": "vendor.Target.changed(java.lang.String)",
        "chain": "app.A.run() → vendor.Target.changed(java.lang.String)",
    },
    {
        "caller": "b",
        "target": "vendor.Target.changed(int)",
        "chain": "app.B.run() → vendor.Target.changed(int)",
    },
    {
        "caller": "dto",
        "target": "class:vendor.model.Dto",
        "chain": "app.Dto.run() → class:vendor.model.Dto",
    },
    {
        "caller": "fuzzy",
        "target": "other.Target.changed(java.lang.String)",
        "chain": "app.Fuzzy.run() → other.Target.changed(java.lang.String)",
    },
)
TARGETS = (
    {
        "coord": "alpha:common",
        "api_name": "vendor.Target.changed",
        "api_signature": "(java.lang.String)",
        "symbol_kind": "method",
        "target": "vendor.Target.changed(java.lang.String)",
    },
    {
        "coord": "alpha:extra",
        "api_name": "vendor.model.Dto",
        "api_signature": "",
        "symbol_kind": "class",
        "target": "class:vendor.model.Dto",
    },
    {
        "coord": "beta:common",
        "api_name": "vendor.Target.changed",
        "api_signature": "(int)",
        "symbol_kind": "method",
        "target": "vendor.Target.changed(int)",
    },
)


def query_index() -> dict:
    reverse = {
        item["target"]: [edge(item["caller"], item["target"])]
        for item in GRAPH_EDGES
        if not item["target"].startswith("other.")
    }
    reverse["method:changed(java.lang.String)"] = [
        edge("a", "vendor.Target.changed(java.lang.String)"),
        edge("fuzzy", "other.Target.changed(java.lang.String)"),
    ]
    return {
        "schema": "java-upgrade-analyzer.s5-query-index.v1",
        "methods": METHODS,
        "lookup_keys_by_symbol": {
            key: [value["qualified_key"]] for key, value in METHODS.items()
        },
        "reverse_edges": reverse,
        "target_apis": [
            {key: value for key, value in item.items() if key != "target"}
            for item in TARGETS
        ],
        "stats": {
            "methods_indexed": len(METHODS),
            "reverse_edge_keys": len(reverse),
            "target_apis_indexed": len(TARGETS),
        },
    }


class PublicQueryCliBlackboxTest(unittest.TestCase):
    def test_all_public_query_modes_match_closed_truth_and_reference_walk(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report"
            index = report / ".runtime" / "indexes" / "s5_query_index.json"
            index.parent.mkdir(parents=True)
            index.write_text(
                json.dumps(query_index(), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            for case in TRUTH["cases"]:
                oracle_chains = expected_chains(
                    GRAPH_EDGES, TARGETS, case["arguments"]
                )
                self.assertEqual(
                    oracle_chains, case["expected"]["chains"], case["id"]
                )
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts" / "s5_query_call_chain.py"),
                        "--report-dir", str(report),
                        *case["arguments"], "--json",
                    ],
                    cwd=str(ROOT),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                    timeout=30,
                )
                self.assertEqual(
                    completed.returncode, 0,
                    f"{case['id']}: {completed.stderr}",
                )
                actual = json.loads(completed.stdout)
                projection = {
                    key: actual[key] for key in case["expected"]
                }
                self.assertEqual(projection, case["expected"], case["id"])


if __name__ == "__main__":
    unittest.main()
