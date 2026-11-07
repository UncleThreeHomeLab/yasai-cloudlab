"""Accepted protection delivery converges reviewed YAML without ever restoring."""
import json
from pathlib import Path
import re
import tempfile
import unittest

from jinja2 import Template
import yaml

import protection


ROOT = Path(__file__).resolve().parents[4]
CATALOG = {'catalog': [{'approval': {'name': 'prices'},
                        'definition': {'name': 'prices',
                                       'persistence': {'enabled': True},
                                       'data': {'database': {'name': 'prices'},
                                                'bucket': {'name': 'prices-history'}}}}]}


def binding(service='prices', resources=None, destination='approved-offsite', profile=None):
    return {'service': service,
            'protection': {'profile': profile or protection.PROFILE,
                           'resources': resources if resources is not None else [
                               {'kind': 'database', 'reference': 'prices'},
                               {'kind': 'bucket', 'reference': 'prices-history'}],
                           'destinationReference': destination}}


def plan(profiles=None, actions=()):
    profiles = profiles if profiles is not None else protection.load_profiles()
    compiled = protection.compile_host_policy(profiles)
    document = profiles[protection.PROFILE]
    return {'profile': protection.PROFILE, 'policy': compiled['policy'],
            'timers': compiled['timers'],
            'longhorn': protection.compile_longhorn(profiles),
            'data': document['data'], 'harbor': document['harbor'],
            'actions': list(actions), 'credentialsChanged': False}


class ProfileContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profiles = protection.load_profiles()
        cls.accepted = cls.profiles[protection.PROFILE]

    def test_control_plane_matches_backup_owner_policy(self):
        policy = json.loads(protection.BACKUP_POLICY.read_text())
        for snake, camel in protection.CAMEL.items():
            with self.subTest(field=snake):
                self.assertEqual(self.accepted['controlPlane'][camel], policy[snake])

    def test_longhorn_matches_chart_policy(self):
        chart = json.loads(protection.LONGHORN_POLICY.read_text())
        block = self.accepted['longhorn']
        self.assertEqual(block['job'], chart['job_name'])
        for key in ('cron', 'retain', 'concurrency', 'prefix'):
            with self.subTest(field=key):
                self.assertEqual(block[key], chart[key])

    def test_data_matches_data_contract(self):
        contract = json.loads((ROOT / 'platform/data/contract.json').read_text())
        block = self.accepted['data']
        mapping = {'monthlyCalendar': 'monthly_calendar',
                   'localGenerations': 'local_generations',
                   'remoteGenerations': 'remote_generations',
                   'remotePrefix': 'remote_prefix',
                   'maxGenerationBytes': 'max_generation_bytes',
                   'maxDatabaseBytes': 'max_database_bytes',
                   'maxObjectsBytes': 'max_objects_bytes',
                   'maxObjects': 'max_objects',
                   'remoteMaxAgeSeconds': 'remote_max_age_seconds'}
        for camel, snake in mapping.items():
            with self.subTest(field=camel):
                self.assertEqual(block[camel], contract[snake])

    def test_harbor_matches_harbor_policy(self):
        policy = json.loads((ROOT / 'platform/harbor/policy.json').read_text())
        block = self.accepted['harbor']
        mapping = {'monthlyCalendar': 'monthly_calendar',
                   'freshnessCalendar': 'freshness_calendar',
                   'remoteMaxAgeSeconds': 'remote_max_age_seconds',
                   'remotePrefix': 'remote_prefix',
                   'maxGenerationBytes': 'max_generation_bytes',
                   'localGenerations': 'local_generations',
                   'remoteGenerations': 'remote_generations'}
        for camel, snake in mapping.items():
            with self.subTest(field=camel):
                self.assertEqual(block[camel], policy[snake])

    def test_non_day_one_calendar_refused(self):
        document = {'profiles': {protection.PROFILE: dict(self.accepted)}}
        document['profiles'][protection.PROFILE] = dict(
            self.accepted, controlPlane=dict(self.accepted['controlPlane'],
                                             calendar='*-*-02 03:30:00 UTC'))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profiles.yaml'
            path.write_text(yaml.safe_dump(document))
            with self.assertRaises(ValueError):
                protection.load_profiles(path)

    def test_unknown_profile_refused(self):
        document = {'profiles': {'nightly-everything': self.accepted}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profiles.yaml'
            path.write_text(yaml.safe_dump(document))
            with self.assertRaises(ValueError):
                protection.load_profiles(path)

    def test_profile_name_matches_credential_reconciler_contract(self):
        from playbooks.secrets.files.reconcile import PROTECTION_PROFILE
        self.assertEqual(protection.PROFILE, PROTECTION_PROFILE)


class BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requests = protection.catalog_requests(CATALOG)

    def test_plan_example_binding_accepted(self):
        validated = protection.validate_binding(binding(), 'prices', self.requests)
        self.assertEqual(validated['destination'], 'approved-offsite')
        self.assertEqual(validated['resources'],
                         [('database', 'prices'), ('bucket', 'prices-history')])

    def test_pvc_binding_accepted(self):
        validated = protection.validate_binding(
            binding(resources=[{'kind': 'pvc', 'reference': 'prices'}]),
            'prices', self.requests)
        self.assertEqual(validated['resources'], [('pvc', 'prices')])

    def test_unknown_profile_refused(self):
        with self.assertRaises(ValueError):
            protection.validate_binding(binding(profile='nightly-everything'),
                                        'prices', self.requests)

    def test_unknown_kind_refused(self):
        with self.assertRaises(ValueError):
            protection.validate_binding(
                binding(resources=[{'kind': 'volume', 'reference': 'prices'}]),
                'prices', self.requests)

    def test_undeclared_resource_refused(self):
        with self.assertRaises(ValueError):
            protection.validate_binding(
                binding(resources=[{'kind': 'database', 'reference': 'shop'}]),
                'prices', self.requests)

    def test_pvc_workload_mismatch_refused(self):
        with self.assertRaises(ValueError):
            protection.validate_binding(
                binding(resources=[{'kind': 'pvc', 'reference': 'shop'}]),
                'prices', self.requests)

    def test_service_directory_mismatch_refused(self):
        with self.assertRaises(ValueError):
            protection.validate_binding(binding(), 'shop', self.requests)

    def test_destination_title_refused(self):
        with self.assertRaises(ValueError):
            protection.validate_binding(binding(destination='Approved Offsite!'),
                                        'prices', self.requests)

    def test_extra_keys_refused(self):
        document = binding()
        document['protection']['restore'] = True
        with self.assertRaises(ValueError):
            protection.validate_binding(document, 'prices', self.requests)

    def test_empty_and_oversized_resources_refused(self):
        with self.assertRaises(ValueError):
            protection.validate_binding(binding(resources=[]), 'prices', self.requests)
        with self.assertRaises(ValueError):
            protection.validate_binding(binding(resources=[
                {'kind': 'bucket', 'reference': 'prices-history'}] * 9),
                'prices', self.requests)

    def test_duplicate_resources_refused(self):
        with self.assertRaises(ValueError):
            protection.validate_binding(binding(resources=[
                {'kind': 'database', 'reference': 'prices'},
                {'kind': 'database', 'reference': 'prices'}]), 'prices', self.requests)

    def test_schema_file_enforces_binding_shape(self):
        import jsonschema
        schema = json.loads(protection.BINDING_SCHEMA.read_text())
        jsonschema.validate(binding(), schema)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(binding(profile='other'), schema)

    def test_coverage_rows_split_by_owner(self):
        profiles = protection.load_profiles()
        rows = protection.coverage(
            protection.validate_binding(binding(), 'prices', self.requests), profiles)
        self.assertEqual([(row['kind'], row['coverage']) for row in rows],
                         [('database', 'covered'), ('bucket', 'covered')])
        rows = protection.coverage(protection.validate_binding(
            binding(resources=[{'kind': 'pvc', 'reference': 'prices'}]),
            'prices', self.requests), profiles)
        self.assertEqual(rows[0]['coverage'], 'uncovered')


class CompileTests(unittest.TestCase):
    def test_compiled_host_policy_matches_setup_bytes(self):
        compiled = protection.compile_host_policy(protection.load_profiles())
        self.assertEqual(protection.policy_bytes(compiled['policy']),
                         protection.BACKUP_POLICY.read_bytes())

    def test_rendered_timers_match_setup_template(self):
        template = Template((ROOT / 'ansible/playbooks/backup/templates/timer.j2').read_text())
        compiled = protection.compile_host_policy(protection.load_profiles())
        for name, calendar in compiled['timers'].items():
            with self.subTest(timer=name):
                self.assertEqual(
                    protection.render_timer(name, calendar),
                    template.render(item={'name': name, 'calendar': calendar}).encode())

    def test_unknown_timer_refused(self):
        with self.assertRaises(ValueError):
            protection.render_timer('cloudlab-recovery-extra', 'hourly')

    def test_longhorn_parity_with_accepted_chart(self):
        compiled = protection.compile_longhorn(protection.load_profiles())
        self.assertTrue(protection.check_longhorn_parity(compiled))
        with self.assertRaises(ValueError):
            protection.check_longhorn_parity({**compiled, 'retain': 2})


class PlanGuardTests(unittest.TestCase):
    def test_compiled_plan_accepted(self):
        self.assertEqual(protection.plan_guard(plan())['profile'], protection.PROFILE)

    def test_unowned_action_refused(self):
        for action in ('restore', 'delete', 'export', 'start', 'enable'):
            with self.subTest(action=action), self.assertRaises(ValueError):
                protection.plan_guard(plan(actions=[action]))

    def test_monthly_window_refused(self):
        guarded = plan()
        guarded['policy'] = dict(guarded['policy'], calendar='*-*-02 03:30:00 UTC')
        with self.assertRaises(ValueError):
            protection.plan_guard(guarded)

    def test_rare_freshness_refused(self):
        guarded = plan()
        guarded['timers'] = dict(guarded['timers'],
                                 **{'cloudlab-recovery-freshness': '*-*-01 07:00:00 UTC'})
        with self.assertRaises(ValueError):
            protection.plan_guard(guarded)

    def test_short_retention_window_refused(self):
        guarded = plan()
        guarded['policy'] = dict(guarded['policy'], max_age_seconds=86400)
        with self.assertRaises(ValueError):
            protection.plan_guard(guarded)

    def test_timer_set_refused(self):
        guarded = plan()
        guarded['timers'] = {'cloudlab-recovery': guarded['timers']['cloudlab-recovery']}
        with self.assertRaises(ValueError):
            protection.plan_guard(guarded)

    def test_longhorn_drift_refused(self):
        guarded = plan()
        guarded['longhorn'] = dict(guarded['longhorn'], cron='0 3 2 * *')
        with self.assertRaises(ValueError):
            protection.plan_guard(guarded)
        guarded['longhorn'] = dict(guarded['longhorn'], cron='0 3 1 * *', retain=0)
        with self.assertRaises(ValueError):
            protection.plan_guard(guarded)

    def test_digests_stable_and_binding_sensitive(self):
        first, second = protection.plan_digest(plan()), protection.plan_digest(plan())
        self.assertRegex(first, r'^[a-f0-9]{64}$')
        self.assertEqual(first, second)
        changed = plan(actions=['write-policy'])
        self.assertNotEqual(protection.plan_digest(changed), first)
        profiles_bytes = (ROOT / 'platform/recovery/profiles.yaml').read_bytes()
        digest = protection.binding_digest(profiles_bytes, {'prices': b'one', 'shop': b'two'})
        self.assertEqual(digest, protection.binding_digest(
            profiles_bytes, {'shop': b'two', 'prices': b'one'}))
        self.assertNotEqual(digest, protection.binding_digest(profiles_bytes, {'prices': b'one'}))

    def test_approval_binds_exact_inputs_and_plan(self):
        binding_hex, digest = 'ab' * 32, 'cd' * 32
        current, approved = protection.validate_approval(
            'binding: "%s"\nplan: "%s"\n' % (binding_hex, digest), binding_hex)
        self.assertTrue(current)
        self.assertEqual(approved, digest)
        current, _ = protection.validate_approval(
            'binding: "%s"\nplan: "%s"\n' % (binding_hex, digest), '00' * 32)
        self.assertFalse(current)
        for text in ('binding: "%s"\n' % binding_hex, 'binding: nope\nplan: "%s"\n' % digest,
                     'binding: "%s"\nplan: "%s"\nextra: 1\n' % (binding_hex, digest)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                protection.validate_approval(text, binding_hex)


class HostCommandTests(unittest.TestCase):
    FORBIDDEN = ('start', 'restart', 'enable', 'monthly', 'initial', 'restore',
                 'recover', 'delete', 'export', 'retrieve')

    def commands(self):
        compiled = protection.compile_host_policy(protection.load_profiles())
        policy = protection.HOST_POLICY_PATH
        timer = protection.TIMER_DIR + '/cloudlab-recovery.timer'
        return [protection.stage_command(policy, '0600'), protection.verify_command(policy),
                protection.verify_staged_command(policy), protection.finalize_command(policy),
                protection.stage_command(timer, '0644'), protection.verify_command(timer),
                protection.finalize_command(timer), protection.daemon_reload_command(),
                protection.list_timers_command(),
                protection.timer_state_command('cloudlab-recovery'),
                protection.freshness_command(), protection.job_free_command(),
                protection.read_command(protection.HOST_CREDENTIALS_PATH)]

    def test_delivery_vocabulary_never_runs_recovery(self):
        for command in self.commands():
            tokens = [token.strip('\'"') for token in re.split(r'[\s=;|]+', command)]
            with self.subTest(command=command):
                for word in self.FORBIDDEN:
                    self.assertNotIn(word, tokens)
                if 'systemctl' in tokens:
                    self.assertTrue('daemon-reload' in tokens or 'show' in tokens)
                if 'backup.py' in command:
                    self.assertIn('freshness', tokens)

    def test_unmanaged_paths_refused(self):
        service = '/etc/systemd/system/cloudlab-recovery.service'
        with self.assertRaises(ValueError):
            protection.stage_command(service, '0600')
        for command in (protection.verify_command, protection.finalize_command,
                        protection.read_command):
            with self.subTest(command=command.__name__), self.assertRaises(ValueError):
                command(service)
        with self.assertRaises(ValueError):
            protection.timer_state_command('cloudlab-recovery-extra')


class TimerStateTests(unittest.TestCase):
    def test_two_line_active_enabled_parses(self):
        self.assertEqual(protection.parse_timer_state('active\nenabled'),
                         {'active': True, 'enabled': True})
        self.assertEqual(protection.parse_timer_state('inactive\ndisabled'),
                         {'active': False, 'enabled': False})

    def test_wrong_line_count_refuses_delivery(self):
        for output in ('active', 'active\nmasked\nenabled', ''):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                protection.parse_timer_state(output)


if __name__ == '__main__':
    unittest.main()
