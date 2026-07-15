import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from data_contract_analysis import compare_jar_data_contracts
from s4_contract import validate_row
from s4_jar_compare import collect_data_contract_changes


@unittest.skipUnless(shutil.which("javac"), "javac is required")
class DataContractAnalysisTest(unittest.TestCase):
    def _compile_jar(self, root: Path, name: str, source: str) -> Path:
        source_root = root / f"{name}-src" / "com" / "acme"
        classes_root = root / f"{name}-classes"
        source_root.mkdir(parents=True)
        classes_root.mkdir(parents=True)
        source_file = source_root / "CustomerDto.java"
        source_file.write_text(source, encoding="utf-8")
        subprocess.run(
            ["javac", "-d", str(classes_root), str(source_file)],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        jar_path = root / f"{name}.jar"
        with zipfile.ZipFile(jar_path, "w") as archive:
            for class_file in sorted(classes_root.rglob("*.class")):
                archive.write(class_file, class_file.relative_to(classes_root).as_posix())
        return jar_path

    def test_private_instance_fields_are_compared_from_final_jar_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_jar = self._compile_jar(
                root,
                "old",
                """
                package com.acme;
                public class CustomerDto {
                    private String typeChanged;
                    private int removed;
                    private static final String CONSTANT = "old";
                    class Child { private String value; }
                }
                """,
            )
            new_jar = self._compile_jar(
                root,
                "new",
                """
                package com.acme;
                public class CustomerDto {
                    private long typeChanged;
                    private boolean added;
                    private static final String CONSTANT = "new";
                    class Child { private String value; }
                }
                """,
            )

            rows = compare_jar_data_contracts(
                old_jar,
                new_jar,
                coord="com.acme:customer-contract",
                old_version="1.0",
                new_version="2.0",
            )

        observed = {
            (row["api_name"], row["change_type"]): (
                row.get("old_value"), row.get("new_value")
            )
            for row in rows
        }
        self.assertEqual(
            observed,
            {
                ("com.acme.CustomerDto.added", "DATA_FIELD_ADDED"): ("", "boolean"),
                ("com.acme.CustomerDto.removed", "DATA_FIELD_REMOVED"): ("int", ""),
                ("com.acme.CustomerDto.typeChanged", "DATA_FIELD_TYPE_CHANGED"): (
                    "java.lang.String",
                    "long",
                ),
            },
        )
        self.assertTrue(all(row["symbol_kind"] == "field" for row in rows))
        self.assertTrue(all(row["source"] == "classfile_contract" for row in rows))
        self.assertFalse(any("CONSTANT" in row["api_name"] for row in rows))
        self.assertFalse(any("this$0" in row["api_name"] for row in rows))

    def test_data_contract_rows_are_valid_step4_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_jar = self._compile_jar(
                root,
                "old",
                "package com.acme; public class CustomerDto { private String name; }",
            )
            new_jar = self._compile_jar(
                root,
                "new",
                "package com.acme; public class CustomerDto { private long name; }",
            )
            rows = compare_jar_data_contracts(
                old_jar,
                new_jar,
                coord="com.acme:customer-contract",
                old_version="1.0",
                new_version="2.0",
            )

        self.assertEqual(len(rows), 1)
        self.assertEqual(validate_row(rows[0]), [])

    def test_step4_collects_contract_rows_from_resolved_artifact_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_jar = self._compile_jar(
                root,
                "old",
                "package com.acme; public class CustomerDto { private String name; }",
            )
            new_jar = self._compile_jar(
                root,
                "new",
                "package com.acme; public class CustomerDto { private String name; private int age; }",
            )

            rows = collect_data_contract_changes(
                str(old_jar),
                str(new_jar),
                coord="com.acme:customer-contract",
                old_version="1.0",
                new_version="2.0",
                jdk_current="17",
            )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["api_name"], "com.acme.CustomerDto.age")
        self.assertEqual(rows[0]["change_type"], "DATA_FIELD_ADDED")
        self.assertEqual(validate_row(rows[0]), [])

    def test_internal_service_state_is_not_reported_as_dto_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_jar = self._compile_jar(
                root,
                "old",
                """
                package com.acme;
                public class CustomerDto { }
                class InternalService { private String cache; void run() {} }
                """,
            )
            new_jar = self._compile_jar(
                root,
                "new",
                """
                package com.acme;
                public class CustomerDto { }
                class InternalService { private String cache; private int retryCount; void run() {} }
                """,
            )

            rows = compare_jar_data_contracts(
                old_jar,
                new_jar,
                coord="com.acme:internal-service",
                old_version="1.0",
                new_version="2.0",
            )

        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
