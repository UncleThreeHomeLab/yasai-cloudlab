"""Host DNS receipts use the configure digest; plan scope and review fail closed.

Desired preview intent serves with zero live routes and every successful
cycle republishes status observations copied from intent; bad generations
retain resolvers and unproven entries stay unpublished.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import reconcile

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / 'platform/delivery/previews/runtime'))

import contract

_DIGEST = '7' * 64
_NOW = 1700000000


def _cluster():
    return {'private_routes': [], 'public_routes': [], 'services': [],
            'cluster_gateway': '10.43.0.1', 'tailnet_gateway': '100.64.0.9',
            'certificates': {
                'private': {'ready': True,
                            'names': ['*.internal.example.test', 'login.example.test']},
                'public': {'ready': True, 'names': []}},
            'binary': 'k3s kubectl'}


def _intent(entries, gateways=None):
    return {'format': 1,
            'gateways': gateways if gateways is not None else {'cluster': '10.43.0.1',
                                                                'tailnet': '100.64.0.9'},
            'entries': entries}


def _intent_cm(intent):
    return json.dumps({'metadata': {'name': 'cloudlab-preview-dns-intent', 'namespace': 'argocd',
                                    'labels': {'cloudlab.io/owner': 'cloudlab-previews'}},
                       'data': {'intent.json': json.dumps(intent, sort_keys=True)}})


def _preview_host(instance, prefix='app'):
    return prefix + '-' + instance + '.internal.example.test'


def _with_dns_cycle(fake_ssh, intent):
    """Stub the intent read and status write around a host-focused fake."""

    def wrapper(prefix, host, command, input=None):
        if command.startswith('k3s kubectl get configmap'):
            return _intent_cm(intent)
        if command.startswith('k3s kubectl apply'):
            return 'configmap/cloudlab-preview-dns-status configured'
        return fake_ssh(prefix, host, command, input)

    return wrapper


def _run_dns_cycle(intent, cluster=None, declared=None, absent=frozenset(), absent_output=None,
                   apply_fail=False, dns_ready=True, prior=None, sink=None):
    """Drive one DNS cycle; absent names the FQDNs proven absent on both hosts.

    sink collects applied manifests and commands even when the cycle raises,
    so failure cells can assert nothing was published.
    """
    applied, commands = [], []
    if cluster is None:
        cluster = _cluster()
    if declared is None:
        declared = DnsReceiptTests.declared

    def fake_ssh(prefix, host, command, input=None):
        commands.append(command)
        if command.startswith('k3s kubectl get configmap'):
            if intent is None:
                raise RuntimeError('configmaps "cloudlab-preview-dns-intent" not found')
            return _intent_cm(intent) if isinstance(intent, dict) else intent
        if command.startswith('k3s kubectl apply'):
            if apply_fail:
                raise RuntimeError('status write failed')
            applied.append(json.loads(input))
            return 'configmap/cloudlab-preview-dns-status configured'
        if command.startswith('cat /var/lib/cloudlab/private-dns/inputs.json'):
            if prior is None:
                raise RuntimeError('no live generation')
            return json.dumps(prior)
        if command.startswith('cat /var/lib/cloudlab/private-dns/generation'):
            return _DIGEST
        if 'dns_host.py absent ' in command:
            if absent_output is not None:
                return absent_output
            fqdn = command.rsplit(' ', 1)[1]
            if fqdn in absent:
                return json.dumps({'absent': [fqdn]})
            raise RuntimeError('name still resolves')
        return json.dumps({'changed': True, 'dns_ready': dns_ready, 'digest': _DIGEST})

    try:
        with patch.object(reconcile, 'ssh', side_effect=fake_ssh):
            with patch.dict(os.environ, {'VM_HOST': 'vm1', 'VM2_HOST': 'vm2'}):
                result = reconcile.reconcile_dns(declared, DnsReceiptTests.servers,
                                                 DnsReceiptTests.mapping, cluster, _NOW)
    finally:
        if sink is not None:
            sink.update(applied=applied, commands=commands)
    return result, applied, commands


def _published_status(applied):
    assert len(applied) == 1
    manifest = applied[0]
    assert manifest['metadata'] == {'name': 'cloudlab-preview-dns-status', 'namespace': 'argocd',
                                    'labels': {'cloudlab.io/owner': 'cloudlab-previews'}}
    return json.loads(manifest['data']['status.json'])


class DnsReceiptTests(unittest.TestCase):
    declared = {'zone': 'internal.example.test', 'services': [], 'names': [],
                'platformNames': []}
    servers = ['100.64.0.1', '100.64.0.2']
    mapping = {'cloudlab': '100.64.0.1', 'cloudlab-worker': '100.64.0.2'}
    digest = '9' * 64

    def reconcile(self, fake_ssh):
        with patch.object(reconcile, 'ssh',
                          side_effect=_with_dns_cycle(fake_ssh, _intent({}))):
            with patch.dict(os.environ, {'VM_HOST': 'vm1', 'VM2_HOST': 'vm2'}):
                return reconcile.reconcile_dns(self.declared, self.servers,
                                               self.mapping, _cluster())

    def test_configure_digest_compared_against_generation_receipt(self):
        def fake_ssh(prefix, host, command, input=None):
            if command.startswith('cat /var/lib/cloudlab/private-dns/inputs.json'):
                raise RuntimeError('no live generation')
            if command.startswith('cat /var/lib/cloudlab/private-dns/generation'):
                return self.digest
            self.assertNotIn('upstreams', json.loads(input))
            return json.dumps({'changed': True, 'dns_ready': True, 'digest': self.digest})

        result = self.reconcile(fake_ssh)
        self.assertTrue(result['ready'])
        self.assertEqual(result['hosts']['cloudlab']['digest'], self.digest)
        self.assertEqual(result['hosts']['cloudlab-worker']['digest'], self.digest)

    def test_receipt_mismatch_blocks_convergence(self):
        def fake_ssh(prefix, host, command, input=None):
            if command.startswith('cat /var/lib/cloudlab/private-dns/inputs.json'):
                raise RuntimeError('no live generation')
            if command.startswith('cat /var/lib/cloudlab/private-dns/generation'):
                return 'observed-other'
            return json.dumps({'changed': False, 'dns_ready': True, 'digest': 'configured'})

        with self.assertRaisesRegex(RuntimeError, 'Resolver drift'):
            self.reconcile(fake_ssh)

    def test_preview_churn_merges_into_withdrawn_and_added(self):
        old = 'old-0123456789abcdef0123456789abcdef'
        new_instance = 'abcdef0123456789abcdef0123456789'
        new = 'new-' + new_instance
        cluster = _cluster()
        cluster['private_routes'] = [new + '.internal.example.test']
        intent = _intent({new_instance: {'hostname': _preview_host(new_instance, 'new'),
                                         'phase': 'desired'}})

        result, _, _ = _run_dns_cycle(intent, cluster=cluster,
                                      prior={'names': ['a'], 'previews': [old]})
        self.assertEqual(result['hosts']['cloudlab']['withdrawn'], ['a', old])
        self.assertEqual(result['hosts']['cloudlab']['added'], [new])

    def test_blocked_names_stay_unserved(self):
        declared = dict(self.declared, services=[{'service': 'svc'}], names=['svc'])
        cluster = _cluster()
        cluster['services'] = ['svc']

        def fake_ssh(prefix, host, command, input=None):
            if command.startswith('cat /var/lib/cloudlab/private-dns/inputs.json'):
                raise RuntimeError('no live generation')
            if command.startswith('cat /var/lib/cloudlab/private-dns/generation'):
                return self.digest
            return json.dumps({'changed': True, 'dns_ready': True, 'digest': self.digest})

        with patch.object(reconcile, 'ssh',
                          side_effect=_with_dns_cycle(fake_ssh, _intent({}))):
            with patch.dict(os.environ, {'VM_HOST': 'vm1', 'VM2_HOST': 'vm2'}):
                result = reconcile.reconcile_dns(declared, self.servers,
                                                 self.mapping, cluster)
        self.assertEqual(result['blocked'], ['svc'])
        self.assertEqual(result['previews'], [])
        self.assertFalse(result['ready'])

    def test_payload_artifact_pins_extracted_binary(self):
        lock = json.loads((reconcile.ROOT / 'platform/connectivity/private-dns/artifact.lock.json')
                          .read_text())
        seen = {}

        def fake_ssh(prefix, host, command, input=None):
            if command.startswith('cat /var/lib/cloudlab/private-dns/inputs.json'):
                raise RuntimeError('no live generation')
            if command.startswith('cat /var/lib/cloudlab/private-dns/generation'):
                return self.digest
            seen[prefix] = json.loads(input)
            return json.dumps({'changed': True, 'dns_ready': True, 'digest': self.digest})

        result = self.reconcile(fake_ssh)
        self.assertTrue(result['ready'])
        self.assertEqual(seen['VM']['artifact'], lock['binary_sha256'])
        self.assertEqual(seen['VM2']['artifact'], lock['binary_sha256'])

    def test_redact_reports_preview_counts(self):
        status = {'dns': {'ready': True, 'names': ['a'], 'blocked': [],
                          'previews': ['p1', 'p2'], 'platform': [],
                          'unrouted_platform': [],
                          'hosts': {'h': {'changed': False, 'digest': 'd' * 64,
                                         'withdrawn': ['x'], 'added': []}}}}
        trimmed = reconcile.redact(status)
        self.assertEqual(trimmed['dns']['previews'], 2)
        self.assertNotIn('p1', json.dumps(trimmed))


class PlanScopeTests(unittest.TestCase):
    def test_retirement_destroy_uses_service_resource(self):
        document = {'resource_changes': [
            {'address': 'cloudflare_zero_trust_access_application.service_application["service_old"]',
             'change': {'actions': ['delete']}},
            {'address': 'cloudflare_zero_trust_tunnel_cloudflared_config.routing',
             'change': {'actions': ['update']}},
            {'address': 'cloudflare_dns_record.service_publication["service_old"]',
             'change': {'actions': ['delete']}},
        ]}
        self.assertTrue(reconcile.plan_owned_scope(document, set(), {'service_old'}))

    def test_base_application_change_refused(self):
        document = {'resource_changes': [
            {'address': 'cloudflare_zero_trust_access_application.application["fixture"]',
             'change': {'actions': ['update']}},
        ]}
        with self.assertRaisesRegex(RuntimeError, 'Unowned'):
            reconcile.plan_owned_scope(document, {'service_new'}, set())


class ResolverSyncTests(unittest.TestCase):
    files_dir = Path(reconcile.__file__).resolve().parent

    def run_sync(self, fake_ssh):
        with patch.object(reconcile, 'ssh', side_effect=fake_ssh):
            with patch.dict(os.environ, {'VM_HOST': 'vm1', 'VM2_HOST': 'vm2'}):
                reconcile.ensure_resolver_scripts()

    def test_current_remote_skips_upload(self):
        calls = []

        def fake_ssh(prefix, host, command, input=None):
            calls.append((prefix, command, input))
            name = command.rsplit('/', 1)[1]
            digest = hashlib.sha256((self.files_dir / name).read_bytes()).hexdigest()
            return digest + '  ' + name

        self.run_sync(fake_ssh)
        self.assertTrue(calls)
        for _, command, payload in calls:
            self.assertTrue(command.startswith('sha256sum '), command)
            self.assertIsNone(payload)

    def test_stale_remote_uploads_exact_bytes_then_reverifies(self):
        uploads = {}
        remote = {}

        def fake_ssh(prefix, host, command, input=None):
            name = command.rsplit('/', 1)[1].split()[0]
            if command.startswith('sha256sum '):
                if (prefix, name) not in remote:
                    raise RuntimeError('missing on host')
                return remote[(prefix, name)] + '  ' + name
            self.assertIn('install -m 0600 /dev/stdin ', command)
            uploads[(prefix, name)] = input
            remote[(prefix, name)] = hashlib.sha256(input.encode('utf-8')).hexdigest()
            return ''

        self.run_sync(fake_ssh)
        for prefix in ('VM', 'VM2'):
            for name in reconcile.RESOLVER_FILES:
                local = (self.files_dir / name).read_bytes().decode('utf-8')
                self.assertEqual(uploads[(prefix, name)], local)

    def test_failed_reverify_refuses_convergence(self):
        def fake_ssh(prefix, host, command, input=None):
            if command.startswith('sha256sum '):
                return '0' * 64 + '  stale'
            return ''

        with self.assertRaisesRegex(RuntimeError, 'sync failed'):
            self.run_sync(fake_ssh)


class PlanDigestTests(unittest.TestCase):
    def test_ignores_serialization_noise_and_order(self):
        change = {'address': 'a', 'change': {'actions': ['update'], 'after': {'x': 1}}}
        noop = {'address': 'z', 'change': {'actions': ['no-op'], 'after': {'x': 9}}}
        first = reconcile.plan_digest({'resource_changes': [change, noop],
                                       'timestamp': 't1', 'noise': [3, 1]})
        second = reconcile.plan_digest({'noise': [1], 'resource_changes': [noop, change],
                                        'timestamp': 't2'})
        self.assertEqual(first, second)

    def test_changes_with_planned_values(self):
        base = {'resource_changes': [
            {'address': 'a', 'change': {'actions': ['update'], 'after': {'x': 1}}}]}
        self.assertNotEqual(reconcile.plan_digest(base), reconcile.plan_digest(
            {'resource_changes': [
                {'address': 'a', 'change': {'actions': ['update'],
                                            'after': {'x': 2}}}]}))


class ReviewGuardTests(unittest.TestCase):
    def test_retired_review_flag_fails_with_migration_error(self):
        with self.assertRaisesRegex(SystemExit, 'retired; approval comes from the merged Git binding'):
            reconcile.main(['once', '--review', '0' * 64])

    def test_unapproved_private_service_blocks_resolvers(self):
        declared = dict(DnsReceiptTests.declared,
                        services=[{'service': 'ghost', 'name': 'ghost', 'backend': 'web',
                                   'path': '/', 'port': 8080}],
                        names=['ghost'])
        with patch.object(reconcile, 'ssh', side_effect=RuntimeError('no SSH in test')):
            with patch.dict(os.environ, {'VM_HOST': 'vm1', 'VM2_HOST': 'vm2'}):
                with self.assertRaisesRegex(RuntimeError, 'lack approved services'):
                    reconcile.reconcile_dns(declared, DnsReceiptTests.servers,
                                            DnsReceiptTests.mapping, _cluster())


class DnsIntentTests(unittest.TestCase):
    """Desired intent serves with zero routes; bad generations retain resolvers."""

    def test_desired_serves_with_zero_routes_and_publishes(self):
        instance = '1' * 32
        intent = _intent({instance: {'hostname': _preview_host(instance), 'phase': 'desired'}})
        cluster = _cluster()
        self.assertEqual(cluster['private_routes'], [])

        result, applied, commands = _run_dns_cycle(intent, cluster=cluster)

        self.assertEqual(result['previews'], ['app-' + instance])
        self.assertEqual(result['routed'], [])
        self.assertEqual(result['unintended_routes'], [])
        self.assertEqual(result['intent'], {'desired': [instance], 'retiring': []})
        self.assertEqual(result['status'], {'published': [instance], 'absent': [], 'omitted': []})
        status = _published_status(applied)
        contract.dns_status(status)
        entry = status['entries'][instance]
        self.assertEqual(entry['hostname'], _preview_host(instance))
        self.assertEqual(entry['observations'],
                         [{'host': 'cloudlab', 'state': 'published', 'observedAt': _NOW},
                          {'host': 'cloudlab-worker', 'state': 'published', 'observedAt': _NOW}])
        self.assertIn('k3s kubectl get configmap cloudlab-preview-dns-intent -n argocd -o json',
                      commands)
        self.assertIn('k3s kubectl apply -f -', commands)

    def test_invalid_intent_retains_resolvers(self):
        intent = _intent({'zz': {'hostname': _preview_host('1' * 32), 'phase': 'desired'}})
        with self.assertRaisesRegex(RuntimeError, 'intent is invalid'):
            _run_dns_cycle(intent)
        with self.assertRaisesRegex(RuntimeError, 'intent is invalid'):
            _run_dns_cycle(json.dumps({'metadata': {}}))

    def test_gateway_mismatch_retains_resolvers(self):
        intent = _intent({'1' * 32: {'hostname': _preview_host('1' * 32), 'phase': 'desired'}},
                         gateways={'cluster': '10.43.9.9', 'tailnet': '100.64.0.9'})
        with self.assertRaisesRegex(RuntimeError, 'differ from live gateways'):
            _run_dns_cycle(intent)

    def test_zone_violation_retains_resolvers(self):
        instance = '2' * 32
        intent = _intent({instance: {'hostname': 'app-' + instance + '.internal.other.test',
                                     'phase': 'desired'}})
        with self.assertRaisesRegex(RuntimeError, 'zone or label shape'):
            _run_dns_cycle(intent)

    def test_collision_with_served_names_refuses(self):
        instance = '3' * 32
        label = 'app-' + instance
        declared = dict(DnsReceiptTests.declared, services=[{'service': 'svc'}], names=[label])
        cluster = _cluster()
        cluster['services'] = ['svc']
        cluster['private_routes'] = [label + '.internal.example.test']
        intent = _intent({instance: {'hostname': _preview_host(instance), 'phase': 'desired'}})
        with self.assertRaisesRegex(RuntimeError, 'collide.*' + label):
            _run_dns_cycle(intent, cluster=cluster, declared=declared)

    def test_overflow_refuses(self):
        entries = {'%032x' % index: {'hostname': _preview_host('%032x' % index, 'app%02d' % index),
                                     'phase': 'desired'}
                   for index in range(21)}
        with self.assertRaisesRegex(RuntimeError, 'exceed their bound'):
            _run_dns_cycle(_intent(entries))

    def test_unreadable_intent_retains_resolvers(self):
        with self.assertRaisesRegex(RuntimeError, 'intent is unreadable'):
            _run_dns_cycle('')
        with self.assertRaisesRegex(RuntimeError, 'intent is unreadable'):
            _run_dns_cycle('not-json{{{')

    def test_missing_intent_propagates_without_publishing(self):
        sink = {}
        with self.assertRaisesRegex(RuntimeError, 'not found'):
            _run_dns_cycle(None, sink=sink)
        self.assertEqual(sink['applied'], [])


class DnsStatusPublishTests(unittest.TestCase):
    """Status observations are copied from intent; unproven entries stay unpublished."""

    def test_retiring_proves_absent_and_publishes(self):
        live, gone = '4' * 32, '5' * 32
        intent = _intent({live: {'hostname': _preview_host(live), 'phase': 'desired'},
                          gone: {'hostname': _preview_host(gone), 'phase': 'retiring'}})

        result, applied, commands = _run_dns_cycle(intent, absent={_preview_host(gone)})

        self.assertEqual(result['previews'], ['app-' + live])
        self.assertEqual(result['intent'], {'desired': [live], 'retiring': [gone]})
        self.assertEqual(result['status'], {'published': [live], 'absent': [gone], 'omitted': []})
        status = _published_status(applied)
        contract.dns_status(status)
        self.assertEqual(status['entries'][gone]['observations'],
                         [{'host': 'cloudlab', 'state': 'absent', 'observedAt': _NOW},
                          {'host': 'cloudlab-worker', 'state': 'absent', 'observedAt': _NOW}])
        absent_calls = [command for command in commands if 'dns_host.py absent ' in command]
        self.assertEqual(len(absent_calls), 2)

    def test_unproven_retiring_stays_unpublished(self):
        live, gone = '6' * 32, '7' * 32
        intent = _intent({live: {'hostname': _preview_host(live), 'phase': 'desired'},
                          gone: {'hostname': _preview_host(gone), 'phase': 'retiring'}})

        result, applied, _ = _run_dns_cycle(intent)

        self.assertEqual(result['status'], {'published': [live], 'absent': [], 'omitted': [gone]})
        status = _published_status(applied)
        contract.dns_status(status)
        self.assertEqual(sorted(status['entries']), [live])

    def test_unconfirmed_absent_output_omits_entry(self):
        gone = '8' * 32
        intent = _intent({gone: {'hostname': _preview_host(gone), 'phase': 'retiring'}})

        result, applied, _ = _run_dns_cycle(intent, absent_output=json.dumps({'absent': []}))

        self.assertEqual(result['previews'], [])
        self.assertEqual(result['status']['omitted'], [gone])
        status = _published_status(applied)
        contract.dns_status(status)
        self.assertEqual(status['entries'], {})

    def test_malformed_absent_output_blocks_publish(self):
        gone = '9' * 32
        intent = _intent({gone: {'hostname': _preview_host(gone), 'phase': 'retiring'}})
        sink = {}
        with self.assertRaisesRegex(RuntimeError, 'absent proof is unreadable'):
            _run_dns_cycle(intent, absent_output='garbage{{{', sink=sink)
        self.assertEqual(sink['applied'], [])

    def test_host_failure_publishes_nothing(self):
        intent = _intent({'a' * 32: {'hostname': _preview_host('a' * 32), 'phase': 'desired'}})
        sink = {}
        with self.assertRaisesRegex(RuntimeError, 'Resolver drift'):
            _run_dns_cycle(intent, dns_ready=False, sink=sink)
        self.assertEqual(sink['applied'], [])

    def test_write_failure_propagates(self):
        intent = _intent({'b' * 32: {'hostname': _preview_host('b' * 32), 'phase': 'desired'}})
        with self.assertRaisesRegex(RuntimeError, 'status write failed'):
            _run_dns_cycle(intent, apply_fail=True)

    def test_routes_are_informational_only(self):
        routed_instance, bare_instance = 'c' * 32, 'd' * 32
        static_label = 'static-' + 'e' * 32
        declared = dict(DnsReceiptTests.declared, names=[static_label])
        unintended = 'rogue-' + 'f' * 32
        cluster = _cluster()
        cluster['private_routes'] = [_preview_host(routed_instance),
                                     unintended + '.internal.example.test',
                                     static_label + '.internal.example.test',
                                     'svc.internal.example.test']
        intent = _intent({routed_instance: {'hostname': _preview_host(routed_instance),
                                            'phase': 'desired'},
                          bare_instance: {'hostname': _preview_host(bare_instance),
                                          'phase': 'desired'}})

        result, applied, _ = _run_dns_cycle(intent, cluster=cluster, declared=declared)

        self.assertEqual(result['previews'], ['app-' + routed_instance, 'app-' + bare_instance])
        self.assertEqual(result['routed'], ['app-' + routed_instance])
        self.assertEqual(result['unintended_routes'], [unintended])
        self.assertEqual(len(applied), 1)

    def test_blocked_static_still_serves_and_publishes(self):
        instance = '0' * 32
        declared = dict(DnsReceiptTests.declared, services=[{'service': 'svc'}], names=['svc'])
        cluster = _cluster()
        cluster['services'] = ['svc']
        intent = _intent({instance: {'hostname': _preview_host(instance), 'phase': 'desired'}})

        result, applied, _ = _run_dns_cycle(intent, cluster=cluster, declared=declared)

        self.assertEqual(result['blocked'], ['svc'])
        self.assertFalse(result['ready'])
        self.assertEqual(result['previews'], ['app-' + instance])
        status = _published_status(applied)
        self.assertEqual(sorted(status['entries']), [instance])

    def test_empty_intent_publishes_empty_status(self):
        result, applied, _ = _run_dns_cycle(_intent({}))

        self.assertEqual(result['previews'], [])
        self.assertEqual(result['intent'], {'desired': [], 'retiring': []})
        status = _published_status(applied)
        contract.dns_status(status)
        self.assertEqual(status, {'format': 1,
                                  'gateways': {'cluster': '10.43.0.1', 'tailnet': '100.64.0.9'},
                                  'entries': {}})

    def test_status_copies_intent_values(self):
        instance = 'ab' * 16
        hostname = _preview_host(instance, 'svc9x')
        intent = _intent({instance: {'hostname': hostname, 'phase': 'desired'}})

        _, applied, _ = _run_dns_cycle(intent)

        status = _published_status(applied)
        contract.dns_status(status)
        self.assertEqual(status['gateways'], intent['gateways'])
        self.assertEqual(status['gateways'], {'cluster': '10.43.0.1', 'tailnet': '100.64.0.9'})
        self.assertEqual(status['entries'][instance]['hostname'], hostname)

    def test_redact_counts_intent_and_status(self):
        status = {'dns': {'ready': True, 'names': ['a'], 'blocked': [],
                          'previews': ['p1'], 'platform': [], 'unrouted_platform': [],
                          'routed': ['p1'], 'unintended_routes': ['r1', 'r2'],
                          'intent': {'desired': ['i1'], 'retiring': ['i2', 'i3']},
                          'status': {'published': ['i1'], 'absent': [], 'omitted': ['i2']},
                          'hosts': {'h': {'changed': False, 'digest': 'd' * 64,
                                         'withdrawn': ['x'], 'added': []}}}}
        trimmed = reconcile.redact(status)
        self.assertEqual(trimmed['dns']['routed'], 1)
        self.assertEqual(trimmed['dns']['unintended_routes'], 2)
        self.assertEqual(trimmed['dns']['intent'], {'desired': 1, 'retiring': 2})
        self.assertEqual(trimmed['dns']['status'], {'published': 1, 'absent': 0, 'omitted': 1})
        self.assertNotIn('p1', json.dumps(trimmed))
        self.assertNotIn('i1', json.dumps(trimmed))

    def test_interval_warning(self):
        with patch.object(reconcile, 'dotenv_values',
                          return_value={'CONNECTIVITY_INTERVAL': '700'}):
            with patch.dict(os.environ, {}, clear=True):
                with patch('builtins.print') as warned:
                    config = reconcile.configuration()
        self.assertEqual(config['interval'], 700)
        warned.assert_called_once()
        self.assertIn('freshness', warned.call_args[0][0])
        with patch.object(reconcile, 'dotenv_values',
                          return_value={'CONNECTIVITY_INTERVAL': '300'}):
            with patch.dict(os.environ, {}, clear=True):
                with patch('builtins.print') as silent:
                    config = reconcile.configuration()
        self.assertEqual(config['interval'], 300)
        silent.assert_not_called()


class RetirementJournalTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        worker = patch.object(reconcile, 'WORK', Path(self.folder.name))
        worker.start()
        self.addCleanup(worker.stop)
        self.journal = Path(self.folder.name) / 'retirement-pending.json'

    def test_missing_journal_starts_empty(self):
        self.assertEqual(reconcile.load_pending(), {'public': [], 'private': []})

    def test_round_trip_persists_sorted_names_with_owner_only_mode(self):
        reconcile.save_pending(['b.example.test', 'a.example.test'], ['x.internal.example.test'])
        self.assertEqual(reconcile.load_pending(),
                         {'public': ['a.example.test', 'b.example.test'],
                          'private': ['x.internal.example.test']})
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)

    def test_invalid_journal_refuses_the_cycle(self):
        bodies = ['not-json', '{"public": []}', '{"public": ["a.example.test"], "private": "x"}',
                  '{"public": [""], "private": []}', '{"public": ["has space.test"], "private": []}',
                  '{"public": ["bad/name.test"], "private": []}',
                  '{"public": ["-leading.test"], "private": []}',
                  '{"public": ["%s.test"], "private": []}' % ('x' * 300),
                  '{"public": ["dup.example.test", "dup.example.test"], "private": []}']
        for body in bodies:
            with self.subTest(body=body[:40]):
                self.journal.write_text(body)
                with self.assertRaises(RuntimeError):
                    reconcile.load_pending()

    def test_oversized_pending_names_refuse_to_persist(self):
        with self.assertRaises(RuntimeError):
            reconcile.save_pending(['h%d.example.test' % n for n in range(65)], [])

    def test_foreign_journal_owner_refuses_the_cycle(self):
        reconcile.save_pending(['a.example.test'], [])
        with patch.object(os, 'geteuid', return_value=os.geteuid() + 1):
            with self.assertRaises(RuntimeError):
                reconcile.load_pending()

    def test_tofu_timeout_keeps_shared_state(self):
        with patch.object(reconcile.subprocess, 'run',
                          side_effect=subprocess.TimeoutExpired('tofu', 600)):
            with self.assertRaisesRegex(RuntimeError, 'timed out; shared state retained'):
                reconcile.tofu(Path('.'), {}, 'plan')
