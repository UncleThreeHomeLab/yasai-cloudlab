import copy
import subprocess
import unittest
from unittest.mock import patch

from playbooks.istio.files.kube import condition
from playbooks.services.files import composition_verify as verification, transport
from playbooks.services.tests.fixtures import composition_runtime


class CompositionVerificationTests(unittest.TestCase):
    def test_exact_owned_runtime_and_real_callers_need_no_probe_workloads(self):
        entry, state, get = composition_runtime()
        with patch.object(transport, 'get', side_effect=get), patch.object(
                transport, 'kube', side_effect=['allowed', 'denied', 'allowed']) as kube:
            result = transport.run(entry, 'unused')
        self.assertEqual(result['owned_pods'], 2)
        self.assertEqual(result['probe_pods_created'], 0)
        self.assertTrue(result['cross_node_caller'])
        self.assertEqual([call.args[0] for call in kube.call_args_list], ['exec'] * 3)
        self.assertTrue(all('-I' in call.args and '-S' in call.args for call in kube.call_args_list))

    def test_missing_stale_or_differently_owned_security_authority_fails(self):
        for kind, name, change in (
                ('ValidatingPolicy', 'cloudlab-composition-namespace', lambda obj: obj.clear()),
                ('ValidatingPolicy', 'cloudlab-composition-synthetic', lambda obj: obj['status'].clear()),
                ('ValidatingPolicy', 'cloudlab-composition-synthetic', lambda obj: obj['metadata']['annotations'].update(
                    {'argocd.argoproj.io/tracking-id': 'synthetic-synthetic:forged'})),
                ('ConfigMap', 'composition-synthetic', lambda obj: obj['data'].update({'release.json': '{}'})),
                ('ValidatingPolicy', 'cloudlab-composition-synthetic', lambda obj: obj['spec'].update(failurePolicy='Ignore'))):
            entry, state, get = composition_runtime()
            change(state[(kind, name, 'cloudlab-policy' if kind == 'ConfigMap' else None)])
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                verification.authority(entry, get)

    def test_unhealthy_wrong_owner_and_changed_profile_pods_fail(self):
        for change in (
                lambda pod: pod['status'].update(phase='Pending'),
                lambda pod: pod['metadata']['ownerReferences'][0].update(uid='different-controller'),
                lambda pod: pod['spec']['containers'][0].update(command=['different-command']),
                lambda pod: pod['metadata']['annotations'].clear(),
                lambda pod: pod['spec']['tolerations'][0].update(tolerationSeconds=301)):
            entry, state, get = composition_runtime()
            change(state[('Pod', 'web-pod', entry['approval']['namespace'])])
            with self.assertRaises((RuntimeError, ValueError)):
                verification.owned_pods(entry, entry['approval']['composition']['images'], get, condition)

    def test_missing_broadened_or_foreign_network_authority_fails_before_exec(self):
        for kind, name, change in (
                ('AuthorizationPolicy', 'platform-workloads', lambda obj: obj['spec']['rules'].clear()),
                ('AuthorizationPolicy', 'platform-workloads', lambda obj: obj['metadata']['annotations'].clear()),
                ('NetworkPolicy', 'platform-deny', lambda obj: obj['spec'].update(ingress=[{}])),
                ('Service', 'web', lambda obj: obj['spec'].update(type='LoadBalancer'))):
            entry, state, get = composition_runtime()
            change(state[(kind, name, entry['approval']['namespace'])])
            with patch.object(transport, 'get', side_effect=get), patch.object(transport, 'kube') as kube:
                with self.subTest(kind=kind), self.assertRaises(RuntimeError): transport.composition(entry)
                kube.assert_not_called()

    def test_network_denial_or_health_failure_is_not_success(self):
        for responses in (['denied'], ['allowed', 'allowed'], ['allowed', 'denied', 'denied']):
            entry, _, get = composition_runtime()
            with patch.object(transport, 'get', side_effect=get), patch.object(transport, 'kube', side_effect=responses):
                with self.assertRaises(RuntimeError): transport.composition(entry)

    def test_admission_uses_only_server_dry_runs_with_exact_positive_profile(self):
        entry, _, get = composition_runtime()
        def kube(*args, document, allow_failure):
            self.assertTrue(allow_failure)
            self.assertTrue('--dry-run=server' in args or any('dryRun=All' in arg for arg in args))
            if args[0] == 'replace' and '--raw' not in args:
                return subprocess.CompletedProcess(args, 1, '', 'cloudlab-composition-namespace')
            spec = document['spec']
            denied = ('ephemeralContainers' in spec or spec.get('hostPID') or spec.get('automountServiceAccountToken') or
                spec['containers'][0]['securityContext'].get('privileged') or
                spec['containers'][0].get('command') == ['unapproved-command'])
            return subprocess.CompletedProcess(args, int(bool(denied)), '', 'cloudlab-composition-synthetic' if denied else '')
        result = verification.admission(entry, get, condition, kube)
        self.assertEqual(result['workloads_created'], 0)
        self.assertTrue(result['ephemeral_denied'])
        with self.assertRaises(RuntimeError):
            verification.admission(entry, get, condition, lambda *args, **kwargs: subprocess.CompletedProcess(args, 1, '', 'unrelated API failure'))
