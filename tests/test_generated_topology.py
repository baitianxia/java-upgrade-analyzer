import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generated_topology import (  # noqa: E402
    GenerationDimensions,
    generate_topology,
    materialize_topology,
)


class GeneratedTopologyTest(unittest.TestCase):
    def test_same_seed_has_byte_identical_canonical_manifest(self):
        dimensions = GenerationDimensions.complete()

        first = generate_topology(1729, dimensions)
        second = generate_topology(1729, dimensions)

        self.assertEqual(first.canonical_json(), second.canonical_json())

    def test_different_seeds_change_topology_without_changing_dimensions(self):
        dimensions = GenerationDimensions.complete()

        first = generate_topology(1729, dimensions)
        second = generate_topology(1730, dimensions)

        self.assertNotEqual(first.canonical_json(), second.canonical_json())
        self.assertEqual(first.covered_dimensions(), dimensions.required_values())
        self.assertEqual(second.covered_dimensions(), dimensions.required_values())

    def test_complete_profile_covers_required_topologies_and_unique_identities(self):
        generated = generate_topology(41, GenerationDimensions.complete())
        manifest = json.loads(generated.canonical_json())

        self.assertEqual(
            generated.covered_dimensions(),
            {
                "same_jar",
                "cross_jar",
                "same_coordinate",
                "overload",
                "inheritance",
                "constant",
                "reflection",
                "callback",
            },
        )
        identities = [row["identity"] for row in manifest["truth_edges"]]
        self.assertEqual(len(identities), len(set(identities)))

    def test_materialized_sources_compile_without_external_dependencies(self):
        generated = generate_topology(99, GenerationDimensions.complete())
        with tempfile.TemporaryDirectory(prefix="jua topology ") as tmp:
            result = materialize_topology(generated, Path(tmp))

            self.assertTrue(result.manifest_path.is_file())
            self.assertTrue(result.classes_dir.is_dir())
            self.assertGreater(len(list(result.classes_dir.rglob("*.class"))), 0)

    def test_truth_callers_name_real_generated_methods(self):
        generated = generate_topology(100, GenerationDimensions.complete())
        caller_members = {
            edge.dimension: edge.caller.split("#", 1)[1].split("(", 1)[0]
            for edge in generated.spec.truth_edges
        }

        self.assertEqual(caller_members["same_jar"], "sameJar")
        self.assertEqual(caller_members["same_coordinate"], "sameCoordinate")
        self.assertEqual(caller_members["overload"], "overloaded")


if __name__ == "__main__":
    unittest.main()
