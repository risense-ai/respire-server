"""Offline structure checks; no workflow dispatch or external API calls."""
import unittest
from pathlib import Path
import yaml
import smoke

ROOT = Path(__file__).resolve().parents[2]


class WorkflowSafetyTests(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / '.github/workflows/dev-passkey-smoke.yml').read_text()
        self.workflow = yaml.safe_load(self.text)

    def test_manual_only_fixed_target_and_no_new_secrets(self):
        # PyYAML's YAML 1.1 loader reads the key 'on' as boolean True.
        trigger = self.workflow.get('on', self.workflow.get(True))
        self.assertEqual(trigger, {'workflow_dispatch': None})
        self.assertEqual(self.workflow['permissions'], {'contents': 'read'})
        self.assertNotIn('secrets.', self.text)
        self.assertNotIn('inputs.', self.text)
        self.assertNotIn('--base-url', self.text)
        self.assertNotIn('--local-test', self.text)
        self.assertEqual(smoke.DEV, 'https://api.dev.rsrs.rs')
        self.assertEqual(smoke.SHA, '686f1d1e84721675906e792c71b96cde4772429e')

    def test_single_global_run_and_bounded_linux_job(self):
        self.assertEqual(self.workflow['concurrency'], {
            'group': 'respire-dev-passkey-synthetic-acceptance', 'cancel-in-progress': False})
        job = self.workflow['jobs']['smoke']
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertEqual(job['timeout-minutes'], 40)
        live = next(step for step in job['steps'] if 'smoke.py' in step.get('run', ''))
        self.assertIn('--approve-synthetic-dev --include-expiry', live['run'])
        self.assertEqual(live['timeout-minutes'], 32)
        self.assertLess(smoke.TOTAL_SECONDS, live['timeout-minutes'] * 60)
        self.assertNotIn('continue-on-error', live)

    def test_always_uploads_only_two_public_files(self):
        steps = self.workflow['jobs']['smoke']['steps']
        checkout = steps[0]
        self.assertFalse(checkout['with']['persist-credentials'])
        uploads = [step for step in steps if step.get('uses', '').startswith('actions/upload-artifact@')]
        self.assertEqual(len(uploads), 1)
        upload = uploads[0]
        self.assertEqual(upload['if'], 'always()')
        self.assertEqual(upload['with']['path'].splitlines(), [
            '${{ runner.temp }}/dev-passkey-result/progress.json',
            '${{ runner.temp }}/dev-passkey-result/result.json'])
        self.assertEqual(upload['with']['retention-days'], 7)

    def test_existing_ci_only_runs_offline_safety_tests(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())
        matching = [step for step in workflow['jobs']['check']['steps']
                    if 'scripts/dev-passkey-smoke' in step.get('run', '')]
        self.assertEqual(len(matching), 1)
        self.assertIn('-m unittest discover -s scripts/dev-passkey-smoke -v', matching[0]['run'])
        self.assertNotIn('--approve-synthetic-dev', matching[0]['run'])
        self.assertNotIn('smoke.py', matching[0]['run'])


if __name__ == '__main__':
    unittest.main()
