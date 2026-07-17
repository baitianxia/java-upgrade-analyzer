import codecs
import csv
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import csv_io  # noqa: E402


class CsvIoTest(unittest.TestCase):
    def test_write_emits_one_bom_and_preserves_chinese(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "中文.csv"
            with csv_io.open_csv_write(path) as handle:
                csv.writer(handle).writerows([["结论"], ["已确认影响"]])

            raw = path.read_bytes()
            self.assertTrue(raw.startswith(codecs.BOM_UTF8))
            self.assertEqual(raw.count(codecs.BOM_UTF8), 1)
            with csv_io.open_csv_read(path) as handle:
                self.assertEqual(
                    list(csv.reader(handle)), [["结论"], ["已确认影响"]]
                )

    def test_read_accepts_historical_plain_utf8_without_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.csv"
            path.write_text("coord,结论\ng:a,安全\n", encoding="utf-8")

            with csv_io.open_csv_read(path) as handle:
                row = next(csv.DictReader(handle))

            self.assertEqual(row["coord"], "g:a")
            self.assertEqual(row["结论"], "安全")

    def test_append_upgrades_plain_utf8_and_never_inserts_inner_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "append.csv"
            path.write_text("name\n第一次\n", encoding="utf-8")

            for value in ("第二次", "第三次"):
                with csv_io.open_csv_append(path) as handle:
                    csv.writer(handle).writerow([value])

            raw = path.read_bytes()
            self.assertEqual(raw.count(codecs.BOM_UTF8), 1)
            self.assertTrue(raw.startswith(codecs.BOM_UTF8))
            with csv_io.open_csv_read(path) as handle:
                self.assertEqual(
                    list(csv.reader(handle)),
                    [["name"], ["第一次"], ["第二次"], ["第三次"]],
                )

    def test_append_to_empty_file_emits_one_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.csv"
            path.touch()

            with csv_io.open_csv_append(path) as handle:
                csv.writer(handle).writerow(["中文"])

            raw = path.read_bytes()
            self.assertTrue(raw.startswith(codecs.BOM_UTF8))
            self.assertEqual(raw.count(codecs.BOM_UTF8), 1)


if __name__ == "__main__":
    unittest.main()
