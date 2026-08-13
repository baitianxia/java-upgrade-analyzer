import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import run_step


class TargetModuleContractTest(unittest.TestCase):
    def pinned_context(self, project_scope, **extra):
        commit = "c" * 40
        return {
            "base_branch": "main",
            "current_branch": "upgrade",
            "current_resolved_commit": commit,
            "active_maven_profiles": [],
            "project_scope": project_scope,
            "pinned_source_snapshot": {
                "schema": run_step.PINNED_SOURCE_SNAPSHOT_SCHEMA,
                "commit": commit,
                "project_path": ".",
                "target_module": "",
                "active_maven_profiles": [],
            },
            **extra,
        }

    def test_step0_requests_target_module_with_detected_candidates(self):
        interaction = run_step.build_step0_confirmation_interaction(
            self.pinned_context({
                'candidate_modules': ['service-a', 'service-b'],
            })
        )
        self.assertEqual(interaction['reason_code'], 'step0_confirmation_required')
        self.assertIn('target_module', interaction['required_fields'])
        target_missing = next(
            item for item in interaction['missing_inputs']
            if item['field'] == 'target_module'
        )
        self.assertEqual(target_missing['candidates'], ['service-a', 'service-b'])
        target_row = next(
            item for item in interaction['confirmation_table']['rows']
            if item['label'] == '目标模块'
        )
        self.assertIn('service-a', target_row['base'])
        self.assertIn('service-b', target_row['base'])

    def test_explicit_target_module_remains_in_unified_step0_confirmation(self):
        interaction = run_step.build_step0_confirmation_interaction({
            'base_branch': 'main',
            'current_branch': 'upgrade',
            'target_module': 'service-a',
        })
        self.assertNotIn('target_module', interaction['required_fields'])
        target_row = next(
            item for item in interaction['confirmation_table']['rows']
            if item['label'] == '目标模块'
        )
        self.assertIn('service-a', target_row['base'])

    def test_target_module_response_updates_internal_execution_fields(self):
        updated = run_step.merge_user_response_into_run_context(
            {'modules': ['stale'], 'primary_module': 'stale'},
            {'target_module': 'service-a'},
            Path('.').resolve(),
        )
        self.assertEqual(updated['target_module'], 'service-a')
        self.assertEqual(updated['primary_module'], 'service-a')
        self.assertEqual(updated['modules'], ['service-a'])

    def test_large_module_candidate_set_stays_compact_but_structurally_complete(self):
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

            interaction = run_step.build_step0_confirmation_interaction(
                self.pinned_context(
                    {
                        'candidate_module_details': candidates,
                        'candidate_modules': [
                            item['module'] for item in candidates
                        ],
                    },
                    report_dir=str(report_dir),
                )
            )
        target_missing = next(
            item for item in interaction['missing_inputs']
            if item['field'] == 'target_module'
        )
        self.assertEqual(len(target_missing['candidates']), 22)
        target_row = next(
            item for item in interaction['confirmation_table']['rows']
            if item['label'] == '目标模块'
        )
        self.assertIn('等 22 个', target_row['base'])
        self.assertEqual(interaction['files_to_review'], [])


if __name__ == '__main__':
    unittest.main()
