import ast
import csv
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import csv_io  # noqa: E402
import gate  # noqa: E402
import s2_context_from_deps as step2  # noqa: E402


class CsvEncodingContractTest(unittest.TestCase):
    def test_core_csv_readers_do_not_expose_bom_in_first_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dep_changes.csv"
            fields = [
                "coord",
                "old_version",
                "new_version",
                "change_type",
                "resolution_status",
                "结论",
            ]
            with csv_io.open_csv_write(path) as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "g:a",
                        "old_version": "1",
                        "new_version": "2",
                        "change_type": "升级",
                        "resolution_status": "resolved",
                        "结论": "已确认",
                    }
                )

            self.assertEqual(step2.load_dep_changes(str(path))["g:a"]["结论"], "已确认")
            gate_rows = gate.read_csv_dicts(path, ["coord", "old_version", "new_version"])
            self.assertEqual(gate_rows[0]["coord"], "g:a")


if __name__ == "__main__":
    unittest.main()
