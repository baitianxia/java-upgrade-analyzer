from __future__ import annotations

from pathlib import Path
import sys
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import s4_contract


class Step4ContractTest(unittest.TestCase):
    @staticmethod
    def _valid_row():
        row = {
            field: "value"
            for field in s4_contract.ALL_CHANGED_APIS_FIELDS
            if field not in s4_contract.OPTIONAL_FIELDS
        }
        row.update({
            "change_type": "REMOVED",
            "severity": "P0",
            "source": "classfile_contract",
            "symbol_kind": "method",
            "confirmed": "true",
        })
        return row

    def test_row_validation_covers_absent_blank_valid_and_invalid_fields(self):
        valid = self._valid_row()
        self.assertEqual(s4_contract.validate_row(valid), [])

        absent = s4_contract.validate_row({})
        self.assertTrue(any("coord" in error for error in absent))
        self.assertTrue(any("confirmed" in error for error in absent))

        blank = dict(valid, coord="   ")
        self.assertTrue(any("coord" in error for error in s4_contract.validate_row(blank)))

        for field, invalid in (
            ("change_type", "NOT_A_CHANGE"),
            ("severity", "P9"),
            ("source", "guess"),
            ("symbol_kind", "property"),
            ("confirmed", "yes"),
        ):
            with self.subTest(field=field):
                malformed = dict(valid)
                malformed[field] = invalid
                self.assertTrue(
                    any(field in error for error in s4_contract.validate_row(malformed))
                )

        for confirmed in ("true", "false", True, False):
            with self.subTest(confirmed=confirmed):
                self.assertEqual(
                    s4_contract.validate_row(dict(valid, confirmed=confirmed)),
                    [],
                )

        for optional_enum in (
            "change_type",
            "severity",
            "source",
            "symbol_kind",
        ):
            sparse = dict(valid)
            sparse[optional_enum] = ""
            errors = s4_contract.validate_row(sparse)
            self.assertTrue(any(optional_enum in error for error in errors))

    def test_filename_sanitization_covers_fallback_reserved_noise_and_bounds(self):
        self.assertEqual(s4_contract._sanitize_filename(None), "file")
        self.assertEqual(s4_contract._sanitize_filename(" CON. "), "_CON")
        self.assertEqual(
            s4_contract._sanitize_filename(' a<>:"/\\|?*\x00   b___ '),
            "a_-b",
        )
        bounded = s4_contract._sanitize_filename("x" * 200, max_len=500)
        self.assertLessEqual(len(bounded), 80)
        custom_fallback = s4_contract._sanitize_filename("___", fallback="safe")
        self.assertEqual(custom_fallback, "safe")

    def test_public_filename_builders_cover_short_long_empty_and_reserved_inputs(self):
        self.assertEqual(
            s4_contract.make_api_filename("demo.Widget.run()", "REMOVED"),
            "Widget_run_REMOVED.json",
        )
        self.assertEqual(
            s4_contract.make_api_filename("Widget", ""),
            "Widget_UNKNOWN.json",
        )
        self.assertEqual(
            s4_contract.make_api_filename("CON", "AUX"),
            "_CON__AUX.json",
        )
        self.assertEqual(s4_contract.make_module_filename(""), "module_impacts.json")
        self.assertEqual(s4_contract.make_module_filename("NUL"), "_NUL_impacts.json")
        self.assertEqual(s4_contract.make_per_dependency_dirname(None), "unknown_coord")
        self.assertEqual(
            s4_contract.make_per_dependency_dirname("g:a:tests"),
            "g__a__tests",
        )
        self.assertEqual(
            s4_contract.get_per_dependency_dir("/report", "g:a"),
            Path("/report") / s4_contract.PER_DEPENDENCY_DIRNAME / "g__a",
        )


if __name__ == "__main__":
    unittest.main()
