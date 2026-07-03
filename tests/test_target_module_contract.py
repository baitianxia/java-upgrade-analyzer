import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import run_step


class TargetModuleContractTest(unittest.TestCase):
    def test_ready_entry_inputs_still_require_target_module_confirmation(self):
        interaction = run_step.build_step1_preflight_interaction({
            'base_branch': 'main',
            'current_branch': 'upgrade',
            'project_scope': {'candidate_modules': ['service-a', 'service-b']},
        })
        self.assertEqual(interaction['reason_code'], 'missing_step1_target_module')
        self.assertEqual(interaction['required_fields'], ['target_module'])
        self.assertEqual(interaction['module_candidates'], ['service-a', 'service-b'])

    def test_explicit_target_module_skips_preflight(self):
        interaction = run_step.build_step1_preflight_interaction({
            'base_branch': 'main',
            'current_branch': 'upgrade',
            'target_module': 'service-a',
        })
        self.assertIsNone(interaction)

    def test_target_module_response_updates_legacy_execution_aliases(self):
        updated = run_step.merge_user_response_into_run_context(
            {'modules': ['stale'], 'primary_module': 'stale'},
            {'target_module': 'service-a'},
            Path('.').resolve(),
        )
        self.assertEqual(updated['target_module'], 'service-a')
        self.assertEqual(updated['primary_module'], 'service-a')
        self.assertEqual(updated['modules'], ['service-a'])


if __name__ == '__main__':
    unittest.main()
