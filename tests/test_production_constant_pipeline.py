import json
import hashlib
from copy import deepcopy
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import constant_impact  # noqa: E402
import constant_impact_oracle  # noqa: E402
import business_bytecode_graph  # noqa: E402
import confidence_weighted_tracer  # noqa: E402
import s4_jar_compare  # noqa: E402


JAPICMP = (
    Path.home()
    / ".m2/repository/com/github/siom79/japicmp/japicmp/0.21.2/"
    "japicmp-0.21.2-jar-with-dependencies.jar"
)


@unittest.skipUnless(
    shutil.which("java") and shutil.which("javac") and JAPICMP.is_file(),
    "JDK tools and the pinned JApiCmp artifact are required",
)
class ProductionConstantPipelineTest(unittest.TestCase):
    def _compile_fixture(self, root):
        old_source = root / "old-src/sample/Flags.java"
        new_source = root / "new-src/sample/Flags.java"
        consumer_source = root / "consumer-src/app/Consumer.java"
        old_source.parent.mkdir(parents=True)
        new_source.parent.mkdir(parents=True)
        consumer_source.parent.mkdir(parents=True)
        old_source.write_text(
            'package sample; public class Flags {'
            ' public static final String TEXT = "old";'
            ' public static final char[] DYNAMIC = new char[0]; }',
            encoding="utf-8",
        )
        new_source.write_text(
            "package sample; public class Flags {}",
            encoding="utf-8",
        )
        consumer_source.write_text(
            "package app; public class Consumer {"
            " public String text() { return sample.Flags.TEXT; }"
            " public char[] dynamic() { return sample.Flags.DYNAMIC; } }",
            encoding="utf-8",
        )
        old_classes = root / "old-classes"
        new_classes = root / "new-classes"
        consumer_classes = root / "consumer-classes"
        subprocess.run(
            ["javac", "-d", str(old_classes), str(old_source)],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["javac", "-d", str(new_classes), str(new_source)],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            [
                "javac", "-cp", str(old_classes), "-d", str(consumer_classes),
                str(consumer_source),
            ],
            check=True, capture_output=True, text=True,
        )

        def jar(name, classes, entries):
            target = root / name
            with zipfile.ZipFile(target, "w") as archive:
                for entry in entries:
                    archive.write(classes / entry, entry)
            return target

        return (
            jar("provider-old.jar", old_classes, ["sample/Flags.class"]),
            jar("provider-new.jar", new_classes, ["sample/Flags.class"]),
            jar("consumer.jar", consumer_classes, ["app/Consumer.class"]),
        )

    def test_step4_dynamic_field_discovery_reconciles_with_independent_oracle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_jar, new_jar, consumer_jar = self._compile_fixture(root)
            output_dir = root / "step4"
            output_dir.mkdir()

            _output, rows, jar_info, error = s4_jar_compare.run_japicmp(
                "sample:provider", "1.0", "2.0", str(output_dir), str(JAPICMP),
                old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                old_jar_evidence={"source": "generated_final_artifact"},
                new_jar_evidence={"source": "generated_final_artifact"},
            )

            self.assertIsNone(error)
            self.assertEqual(jar_info["parser_mode"], "xml")
            fields = {
                row["api_name"]: row
                for row in rows
                if row.get("symbol_kind") == "field"
                and row.get("api_name") in {
                    "sample.Flags.TEXT", "sample.Flags.DYNAMIC"
                }
            }
            self.assertEqual(
                set(fields), {"sample.Flags.TEXT", "sample.Flags.DYNAMIC"}
            )
            self.assertIn("CONSTANT_REMOVED", fields["sample.Flags.TEXT"][
                "compatibility_flags"
            ])
            self.assertNotIn("CONSTANT_REMOVED", fields["sample.Flags.DYNAMIC"][
                "compatibility_flags"
            ])
            ledger = constant_impact_oracle.run_constant_oracle(
                old_jar, [consumer_jar], list(fields.values())
            )
            self.assertTrue(ledger.complete, ledger.failures)

            oracle_by_api = {record.api_name: record for record in ledger.records}
            for api_name, row in fields.items():
                analyzer_field = json.loads(row["constant_field_evidence_json"])
                oracle_field = oracle_by_api[api_name]
                self.assertEqual(analyzer_field["status"], "complete")
                self.assertEqual(
                    analyzer_field["descriptor"], oracle_field.descriptor
                )
                self.assertEqual(
                    analyzer_field["has_constant_value"],
                    oracle_field.has_constant_value,
                )
                self.assertEqual(
                    analyzer_field["constant_value"], oracle_field.constant_value
                )
                owner, _, field_name = api_name.rpartition(".")
                analyzer_links = constant_impact.scan_consumer_field_links(
                    [consumer_jar], owner, field_name, oracle_field.descriptor
                )
                self.assertEqual(
                    [item.to_dict() for item in analyzer_links],
                    list(oracle_field.runtime_links),
                )

            methods = {}
            methods_by_qualified = {}
            lookup_keys = {}
            for member, descriptor in (
                ("text", "()Ljava/lang/String;"),
                ("dynamic", "()[C"),
            ):
                symbol = f"app.Consumer.{member}"
                method = SimpleNamespace(
                    symbol_id=symbol,
                    qualified_key=symbol,
                    declared_qualified_key=symbol,
                    class_fqcn="app.Consumer",
                    method_name=member,
                    descriptor=descriptor,
                    owner_type="business",
                    owner_coord="__business__",
                    module="app",
                    is_test=False,
                    evidence_source="current_final_artifact",
                    evidence_authority="current_final_artifact",
                    evidence_type="business_artifact_method",
                    artifact_sha256=hashlib.sha256(
                        consumer_jar.read_bytes()
                    ).hexdigest(),
                    artifact_entry="app/Consumer.class",
                    file=f"{consumer_jar}!/app/Consumer.class",
                    line=0,
                )
                methods[symbol] = method
                methods_by_qualified[symbol] = [method]
                lookup_keys[symbol] = (f"{symbol}()",)
            business_item = {
                "coord": "__business__",
                "jar_path": str(consumer_jar),
                "artifact_entry": "<business-classes>",
                "sha256": hashlib.sha256(consumer_jar.read_bytes()).hexdigest(),
                "evidence_source": "current_final_artifact",
            }
            provider_item = {
                "coord": "sample:provider",
                "jar_path": str(new_jar),
                "artifact_entry": "BOOT-INF/lib/provider-new.jar",
                "sha256": hashlib.sha256(new_jar.read_bytes()).hexdigest(),
                "evidence_source": "current_final_artifact",
            }
            step5_dir = root / "step5"
            step5_dir.mkdir()
            provenance = step5_dir / "evidence/dependencies/build_provenance.json"
            provenance.parent.mkdir(parents=True)
            provenance.write_text(json.dumps({"sides": [{
                "side": "current",
                "artifact_path": str(consumer_jar),
                "artifact_sha256": business_item["sha256"],
            }]}), encoding="utf-8")
            graph = SimpleNamespace(
                report_dir=str(step5_dir),
                methods_by_id=methods,
                methods_by_qualified=methods_by_qualified,
                lookup_keys_by_symbol=lookup_keys,
                reverse_edges={},
                source_artifact_alignment={"status": "aligned"},
                require_current_final_artifact_business_edges=True,
                runtime_dependency_catalog={
                    "status": "complete",
                    "entries": [business_item, provider_item],
                    "by_coord": {
                        "__business__": business_item,
                        "sample:provider": provider_item,
                    },
                    "target_jdk": "17",
                },
            )
            bytecode_edges, metrics = (
                business_bytecode_graph.collect_business_bytecode_edges(
                    [], artifact_catalog=graph.runtime_dependency_catalog
                )
            )
            self.assertEqual(metrics["failures"], [])
            business_bytecode_graph.merge_business_bytecode_edges(
                graph, bytecode_edges
            )
            dynamic_result = confidence_weighted_tracer.trace_api_with_confidence_weighting(
                fields["sample.Flags.DYNAMIC"], graph, {},
                has_packaged_bytecode_fallback=True,
            )
            text_result = confidence_weighted_tracer.trace_api_with_confidence_weighting(
                fields["sample.Flags.TEXT"], graph, {},
                has_packaged_bytecode_fallback=True,
            )

            self.assertEqual(dynamic_result.analysis_status, "reachable")
            self.assertEqual(dynamic_result.runtime_link_impact, "runtime_link_present")
            self.assertEqual(
                text_result.analysis_status, "uncertain", vars(text_result)
            )
            self.assertEqual(text_result.reason_code, "INLINED_CONSTANT_USAGE_UNDETECTABLE")

    def test_dynamic_pipeline_gate_detects_removed_link_and_dropped_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_jar, new_jar, consumer_jar = self._compile_fixture(root)
            output_dir = root / "step4"
            output_dir.mkdir()
            _output, rows, _jar_info, error = s4_jar_compare.run_japicmp(
                "sample:provider", "1.0", "2.0", str(output_dir), str(JAPICMP),
                old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                old_jar_evidence={"source": "generated_final_artifact"},
                new_jar_evidence={"source": "generated_final_artifact"},
            )
            self.assertIsNone(error)
            fields = [row for row in rows if row.get("symbol_kind") == "field"]
            ledger = constant_impact_oracle.run_constant_oracle(
                old_jar, [consumer_jar], fields
            )
            self.assertTrue(ledger.complete, ledger.failures)
            analyzer_rows = [{
                "identity": record.identity,
                "descriptor": record.descriptor,
                "has_constant_value": record.has_constant_value,
                "constant_value": record.constant_value,
                "runtime_links": list(record.runtime_links),
                "consumer_artifact_sha256s": list(
                    record.consumer_artifact_sha256s
                ),
                "old_artifact_sha256": record.old_artifact_sha256,
            } for record in ledger.records]
            oracle_rows = [record.to_dict() for record in ledger.records]
            self.assertFalse(constant_impact_oracle.audit_constant_evidence(
                analyzer_rows, oracle_rows
            )["blocking"])

            removed_link = deepcopy(analyzer_rows)
            dynamic = next(
                item for item in removed_link
                if "sample.Flags.DYNAMIC" in item["identity"]
            )
            dynamic["runtime_links"] = []
            removed_link_audit = constant_impact_oracle.audit_constant_evidence(
                removed_link, oracle_rows
            )
            self.assertEqual(
                removed_link_audit["incorrect_fields"][dynamic["identity"]],
                ["runtime_links"],
            )

            dropped_api_audit = constant_impact_oracle.audit_constant_evidence(
                analyzer_rows[:-1], oracle_rows
            )
            self.assertEqual(len(dropped_api_audit["missing_identities"]), 1)


if __name__ == "__main__":
    unittest.main()
