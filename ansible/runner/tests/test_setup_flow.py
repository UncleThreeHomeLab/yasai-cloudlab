"""Pin the one-time setup gate and read-only verification contracts statically.

Ansible runs only against live servers, so these tests assert the structural
shape instead: setup refuses completed servers before any install stage,
repeatable verification reports no changes and reaches no ownership, drift,
or deletion work, monthly proof never falls through to setup, and the retired
seed-stop injection paths stay gone.
"""
import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
PLAYBOOKS = ROOT / 'ansible/playbooks'
COMPLETION_RECORD = '/var/lib/cloudlab/setup-completed.json'
MIGRATION_STATE = '/var/lib/cloudlab/k3s-migration/state.json'
MIGRATION_RESUME_PHASES = ('new', 'rolled-back')
RETIRED_MARKERS = ('seed-stop', 'STOP_AFTER_SEED', 'stop_after_seed',
                   'interrupted_fixture', 'interruption_test')


def plays(path):
    return yaml.safe_load((PLAYBOOKS / path).read_text())


def resolve(target, base):
    text = str(target)
    if text.startswith('/workspace/'):
        return ROOT / text[len('/workspace/'):]
    return base / text


def iter_tasks(tasks, base):
    for task in tasks or []:
        if any(key in task for key in ('block', 'rescue', 'always')):
            for key in ('block', 'rescue', 'always'):
                yield from iter_tasks(task.get(key), base)
            continue
        target = task.get('ansible.builtin.import_tasks') or task.get('ansible.builtin.include_tasks')
        if isinstance(target, str):
            path = resolve(target, base)
            yield from iter_tasks(yaml.safe_load(path.read_text()), path.parent)
            continue
        yield task


def reachable_tasks(entry):
    found = []
    for play in plays(entry):
        target = play.get('ansible.builtin.import_playbook')
        if target:
            path = resolve(target, PLAYBOOKS)
            for child in yaml.safe_load(path.read_text()):
                found.extend(iter_tasks(child.get('tasks'), path.parent))
            continue
        found.extend(iter_tasks(play.get('tasks'), PLAYBOOKS))
    return found


class SetupFlowTests(unittest.TestCase):
    def test_setup_refuses_completed_servers_before_any_install_stage(self):
        setup = plays('setup.yml')
        self.assertEqual(setup[0]['ansible.builtin.import_playbook'], 'host/000-setup-gate.yml')
        gate = plays('host/000-setup-gate.yml')
        self.assertEqual(len(gate), 1)
        self.assertEqual(gate[0]['hosts'], 'k3s_cluster')
        tasks = list(iter_tasks(gate[0]['tasks'], PLAYBOOKS / 'host'))
        # stat completion record, stat migration checkpoint, slurp checkpoint,
        # refuse on completion record, refuse on unreadable checkpoint,
        # refuse on migration state. Every read is changed_when false.
        self.assertEqual(len(tasks), 6)
        stats = [task['ansible.builtin.stat']['path'] for task in tasks if 'ansible.builtin.stat' in task]
        self.assertEqual(stats, [COMPLETION_RECORD, MIGRATION_STATE])
        slurps = [task for task in tasks if 'ansible.builtin.slurp' in task]
        self.assertEqual(len(slurps), 1)
        self.assertEqual(slurps[0]['ansible.builtin.slurp']['src'], MIGRATION_STATE)
        self.assertEqual(slurps[0].get('changed_when'), False)
        self.assertEqual(slurps[0].get('failed_when'), False)
        fails = [task for task in tasks if 'ansible.builtin.fail' in task]
        self.assertEqual(len(fails), 3)
        for fail in fails:
            self.assertIn('No mutation performed', fail['ansible.builtin.fail']['msg'])
        record_refusal = fails[0]
        # Refuse on record existence without parsing it: absent records resume,
        # present-but-unreadable records still block, never proceed.
        self.assertIn('.stat.exists', str(record_refusal['when']))
        self.assertNotIn('from_json', json.dumps(record_refusal))

    def test_setup_refuses_migration_state_and_unreadable_checkpoints(self):
        gate = plays('host/000-setup-gate.yml')
        tasks = list(iter_tasks(gate[0]['tasks'], PLAYBOOKS / 'host'))
        fails = [task for task in tasks if 'ansible.builtin.fail' in task]
        body = json.dumps(fails[1:])
        # Present-but-unreadable checkpoint fails closed to refuse.
        self.assertIn('migration_checkpoint_content.failed', body)
        # Started or completed migration phases refuse; only fresh or
        # rolled-back checkpoints resume alongside an absent record.
        phase_refusal = json.dumps(fails[2])
        self.assertIn(MIGRATION_STATE, json.dumps(tasks))
        for phase in MIGRATION_RESUME_PHASES:
            self.assertIn(phase, phase_refusal)
        self.assertIn('from_json', phase_refusal)
        # Absent checkpoint skips the read and both migration refusals close out.
        slurp = next(task for task in tasks if 'ansible.builtin.slurp' in task)
        self.assertIn('.stat.exists', str(slurp.get('when')))
        for fail in fails[1:]:
            self.assertIn('migration_checkpoint.stat.exists', str(fail['when']))

    def test_setup_completion_stamp_writes_the_gated_record(self):
        stamp = plays('host/stamp-setup.yml')
        self.assertEqual(len(stamp), 1)
        self.assertEqual(stamp[0]['hosts'], 'k3s_cluster')
        tasks = list(iter_tasks(stamp[0]['tasks'], PLAYBOOKS / 'host'))
        self.assertIn('LAB_SETUP_COMPLETED_REVISION', json.dumps(tasks[0]))
        writes = [task for task in tasks if 'ansible.builtin.copy' in task]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]['ansible.builtin.copy']['dest'], COMPLETION_RECORD)

    def test_verify_reports_no_changes_and_reaches_no_ownership_work(self):
        tasks = reachable_tasks('verify.yml')
        self.assertGreater(len(tasks), 20)
        for task in tasks:
            with self.subTest(task=task.get('name')):
                self.assertNotEqual(task.get('changed_when'), True)
                body = json.dumps(task)
                for marker in ('"accept"', 'verify_gitops', 'drift-only') + RETIRED_MARKERS:
                    self.assertNotIn(marker, body)
                if 'delete' in body:
                    self.assertEqual(task.get('changed_when'), False)
        text = (PLAYBOOKS / 'verify.yml').read_text()
        self.assertNotIn('verify-controller', text)

    def test_monthly_proof_never_falls_through_to_setup(self):
        monthly = plays('monthly-proof.yml')
        imports = [play['ansible.builtin.import_playbook'] for play in monthly]
        self.assertNotIn('setup.yml', ' '.join(imports))
        self.assertEqual(imports, ['longhorn/verify-storage.yml', 'backup/verify.yml',
                                   'longhorn/check-backup-access.yml',
                                   'longhorn/retire-legacy-backup-credential.yml'])

    def test_retired_seed_stop_injection_stays_gone(self):
        offenders = []
        for path in sorted((ROOT / 'ansible').rglob('*')):
            if path.is_file() and path.suffix in ('.py', '.yml') and path.name != 'test_setup_flow.py':
                body = path.read_text()
                if any(marker in body for marker in RETIRED_MARKERS):
                    offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])


if __name__ == '__main__':
    unittest.main()
