import sys
import tempfile
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

    def test_large_module_candidate_set_has_complete_user_review_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / '.upgrade-report'
            candidates = [
                {
                    'module': f'library-{index}',
                    'coord': f'com.acme:library-{index}',
                    'packaging': 'jar',
                    'deploy_hints': [],
                }
                for index in range(21)
            ]
            candidates.append(
                {
                    'module': 'application',
                    'coord': 'com.acme:application',
                    'packaging': 'jar',
                    'deploy_hints': ['spring-boot-maven-plugin'],
                }
            )

            interaction = run_step.build_step1_preflight_interaction(
                {
                    'base_branch': 'main',
                    'current_branch': 'upgrade',
                    'report_dir': str(report_dir),
                    'project_scope': {'candidate_module_details': candidates},
                }
            )
            candidate_file = Path(interaction['files_to_review'][0])
            text = candidate_file.read_text(encoding='utf-8')

        self.assertEqual(interaction['module_candidates'][0]['module'], 'application')
        self.assertTrue(candidate_file.name == 'module_candidates.md')
        self.assertIn('library-20', text)
        self.assertIn('spring-boot-maven-plugin', text)


if __name__ == '__main__':
    unittest.main()
