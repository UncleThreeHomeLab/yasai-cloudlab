"""Exercise shared CI policies with native CEL, including their trusted profile lookup."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

from playbooks.admission.files.chart import render
from playbooks.admission.tests.fixtures import runner


class RunnerPolicyTests(unittest.TestCase):
    def evaluate(self, resources, names, *, profile=None, username=None, results=None):
        good, default_profile = runner()
        profile = profile or default_profile
        policies = [p for p in render(True) if p['metadata']['name'] in names]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {
                'policies.yaml': list(policies), 'pods.yaml': list(resources),
                'values.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Values',
                    'namespaceSelector': [{'name': name, 'labels': {
                        'cloudlab.io/owner': 'ci-platform', 'cloudlab.io/ci-role': 'runner'}}
                        for name in sorted({r['metadata']['namespace'] for r in resources if r['kind'] == 'Pod'})]},
                'context.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Context',
                    'metadata': {'name': 'ci'}, 'spec': {'resources': [profile]}},
                'user.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'UserInfo',
                    'metadata': {'name': 'controller'}, 'userInfo': {'username': username or
                        json.loads(profile['data']['admission.json'])['controller']}},
                'kyverno-test.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Test',
                    'metadata': {'name': 'ci-admission'}, 'policies': ['policies.yaml'],
                    'resources': ['pods.yaml'], 'variables': 'values.yaml', 'userinfo': 'user.yaml',
                    'context': 'context.yaml', 'results': results or [
                        {'isValidatingPolicy': True, 'kind': r['kind'], 'policy': p['metadata']['name'],
                         'resources': [r['metadata']['name']],
                         'result': 'pass' if r['metadata']['name'] == 'accepted' else 'fail'}
                        for r in resources for p in policies]}}
            for name, value in files.items():
                (root / name).write_text(yaml.safe_dump_all(value) if isinstance(value, list) else yaml.safe_dump(value))
            result = subprocess.run(['kyverno', 'test', str(root)], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('error)', result.stdout)

    def test_qualified_runner_passes_both_policies_without_a_builder_exemption(self):
        good, _ = runner()
        self.evaluate([good], ['cloudlab-ci-boundary', 'cloudlab-ci-runner'])

    def test_new_repository_namespace_inherits_the_same_policies(self):
        good, profile = runner()
        namespace = 'cloudlab-ci-public-future-app'
        good['metadata']['namespace'] = profile['metadata']['namespace'] = namespace
        bad = copy.deepcopy(good)
        bad['metadata']['name'] = 'unapproved'
        bad['spec']['containers'][0]['securityContext']['allowPrivilegeEscalation'] = True
        self.evaluate([good, bad], ['cloudlab-ci-runner'], profile=profile)

    def test_runner_permissions_mounts_commands_and_budgets_cannot_escape_the_profile(self):
        good, _ = runner()
        documents = [good]
        changes = {
            'other-account': lambda p: p.update(serviceAccountName='default'),
            'host-users': lambda p: p.update(hostUsers=True),
            'automatic-token': lambda p: p.update(automountServiceAccountToken=True),
            'other-image': lambda p: p['containers'][0].update(image='example.invalid/foreign@sha256:' + 'b' * 64),
            'builder-image': lambda p: p['initContainers'][0].update(image='example.invalid/foreign@sha256:' + 'b' * 64),
            'builder-privilege': lambda p: p['initContainers'][0]['securityContext'].update(privileged=True),
            'builder-unconfined': lambda p: p['initContainers'][0]['securityContext'].update(seccompProfile={'type': 'Unconfined'}),
            'runner-escalation': lambda p: p['containers'][0]['securityContext'].update(allowPrivilegeEscalation=True),
            'large-budget': lambda p: p['containers'][0]['resources']['limits'].update(cpu='8'),
            'other-command': lambda p: p['containers'][0].update(args=['echo bypass']),
            'health-disabled': lambda p: p['containers'][0].pop('livenessProbe'),
            'health-delayed': lambda p: p['containers'][0]['livenessProbe'].update(terminationGracePeriodSeconds=3600),
            'builder-probe': lambda p: p['initContainers'][0]['startupProbe']['exec'].update(command=['true']),
            'builder-credential': lambda p: p['initContainers'][0]['volumeMounts'].append({'name': 'health', 'mountPath': '/stolen'}),
            'extra-secret': lambda p: p['volumes'].append({'name': 'private', 'secret': {'secretName': 'cloudlab-release'}}),
            'extra-env-secret': lambda p: p['containers'][0].update(envFrom=[{'secretRef': {'name': 'cloudlab-release'}}]),
            'env-injection': lambda p: p['containers'][0]['env'].append({'name': 'BASH_ENV', 'value': '/workspace/evil'}),
            'health-volume': lambda p: p['volumes'][5]['projected']['sources'][0]['serviceAccountToken'].update(audience='foreign'),
            'wrong-policy': lambda p: p['volumes'][-1]['configMap'].update(name='unapproved'),
            'extra-sidecar': lambda p: p['containers'].append(copy.deepcopy(p['containers'][0])),
        }
        for name, change in changes.items():
            document = copy.deepcopy(good)
            document['metadata']['name'] = name
            document['spec']['containers'][0]['env'][1]['valueFrom']['secretKeyRef']['name'] = name
            change(document['spec'])
            documents.append(document)
        self.evaluate(documents, ['cloudlab-ci-runner'])

    def test_spoofed_profile_does_not_authorize_a_runner_service_account(self):
        good, _ = runner()
        good['metadata']['name'] = 'unauthorized'
        self.evaluate([good], ['cloudlab-ci-runner'],
                      username='system:serviceaccount:cloudlab-ci-private:cloudlab-ci-health')

    def test_common_boundary_rejects_host_access_debug_and_unbounded_containers(self):
        good, _ = runner()
        documents = [good]
        for name, field, value in (
                ('host-network', 'hostNetwork', True), ('host-pid', 'hostPID', True),
                ('host-ipc', 'hostIPC', True), ('shared-processes', 'shareProcessNamespace', True),
                ('runtime-override', 'runtimeClassName', 'other'),
                ('host-socket', 'volumes', [{'name': 'docker', 'hostPath': {'path': '/var/run/docker.sock'}}]),
                ('persistent-state', 'volumes', [{'name': 'state', 'persistentVolumeClaim': {'claimName': 'private'}}]),
                ('debug', 'ephemeralContainers', [{'name': 'debug', 'image': 'example.invalid/debug@sha256:' + 'b' * 64}])):
            document = copy.deepcopy(good)
            document['metadata']['name'] = name
            document['spec'][field] = value
            documents.append(document)
        for name, change in (
                ('no-resources', lambda c: c.pop('resources')),
                ('no-storage-budget', lambda c: c['resources']['limits'].pop('ephemeral-storage')),
                ('zero-budget', lambda c: c['resources']['limits'].update(cpu='0')),
                ('root', lambda c: c['securityContext'].update(runAsUser=0)),
                ('extra-capability', lambda c: c['securityContext']['capabilities'].update(add=['SYS_ADMIN'])),
                ('unqualified-builder', lambda c: c['securityContext'].update(seccompProfile={'type': 'Unconfined'}))):
            document = copy.deepcopy(good)
            document['metadata']['name'] = name
            change(document['spec']['initContainers'][0])
            documents.append(document)
        self.evaluate(documents, ['cloudlab-ci-boundary'])

    def test_ci_namespaces_cannot_omit_selection_or_weaken_pod_security(self):
        namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {
            'name': 'cloudlab-ci-public-new', 'labels': {'cloudlab.io/owner': 'ci-platform',
                'cloudlab.io/ci-role': 'runner', 'pod-security.kubernetes.io/enforce': 'baseline',
                'pod-security.kubernetes.io/enforce-version': 'v1.36',
                'pod-security.kubernetes.io/audit': 'restricted', 'pod-security.kubernetes.io/warn': 'restricted'}}}
        documents = [namespace]
        results = [{'isValidatingPolicy': True, 'kind': 'Namespace', 'policy': 'cloudlab-ci-namespace',
                    'resources': [namespace['metadata']['name']], 'result': 'pass'}]
        for key, value in (('cloudlab.io/owner', 'unmanaged'), ('cloudlab.io/ci-role', 'controller'),
                           ('pod-security.kubernetes.io/enforce', 'privileged')):
            resource = copy.deepcopy(namespace)
            resource['metadata']['name'] += '-' + str(len(documents))
            resource['metadata']['labels'][key] = value
            documents.append(resource)
            results.append(dict(results[0], resources=[resource['metadata']['name']], result='fail'))
        self.evaluate(documents, ['cloudlab-ci-namespace'], results=results)
