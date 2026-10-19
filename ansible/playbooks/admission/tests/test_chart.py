import copy
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

from playbooks.admission.files.chart import check, render, ROOT
from playbooks.admission.tests.fixtures import pod


class AdmissionTests(unittest.TestCase):
    def test_native_chart_retains_apis_without_hooks_secrets_or_host_privileges(self):
        self.assertEqual(check()['runtime_images'], 3)

    def test_native_cli_rejects_tagged_unbounded_and_token_enabled_workloads(self):
        policy = render(True)[0]
        # Native test uses a matching namespace; production selector remains intact.
        resources = [pod()]
        for name, field, value in (('mutable-image', 'image', 'example.invalid/public/app:latest'),
                                   ('missing-limits', 'resources', {'requests': {'cpu': '10m', 'memory': '16Mi'}})):
            resource = pod(name)
            resource['spec']['containers'][0][field] = value
            resources.append(resource)
        for name, value in (('token-enabled', True), ('token-default', None)):
            resource = pod(name)
            if value is None:
                del resource['spec']['automountServiceAccountToken']
            else:
                resource['spec']['automountServiceAccountToken'] = value
            resources.append(resource)
        resource = pod('mutable-init')
        resource['spec']['initContainers'] = [copy.deepcopy(resource['spec']['containers'][0])]
        resource['spec']['initContainers'][0]['image'] = 'example.invalid/init:latest'
        resources.append(resource)
        resource = pod('unbounded-cpu')
        resource['spec']['containers'][0]['resources']['limits']['cpu'] = '0'
        resources.append(resource)
        resource = pod('projected-token')
        resource['spec']['volumes'] = [{'name': 'api', 'projected': {
            'sources': [{'serviceAccountToken': {'path': 'token'}}]}}]
        resources.append(resource)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'policy.yaml').write_text(yaml.safe_dump(policy))
            (directory / 'resources.yaml').write_text(yaml.safe_dump_all(resources))
            (directory / 'values.yaml').write_text(yaml.safe_dump({
                'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Values',
                'namespaceSelector': [{'name': 'cloudlab-app-proof', 'labels': {'cloudlab.io/owner': 'service-platform'}}]}))
            (directory / 'kyverno-test.yaml').write_text(yaml.safe_dump({
                'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Test', 'metadata': {'name': 'workload-contract'},
                'policies': ['policy.yaml'], 'resources': ['resources.yaml'], 'variables': 'values.yaml',
                'results': [{'isValidatingPolicy': True, 'kind': 'Pod', 'policy': policy['metadata']['name'],
                             'resources': [resource['metadata']['name']],
                             'result': 'pass' if resource['metadata']['name'] == 'accepted' else 'fail'} for resource in resources]}))
            result = subprocess.run(['kyverno', 'test', str(directory)], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('8 tests passed', result.stdout)

    def test_root_restricts_policy_sources_and_does_not_grant_application_admin_access(self):
        result = subprocess.run(['helm', 'template', 'root', str(ROOT / 'gitops/roots/public')],
                                capture_output=True, text=True, timeout=90, check=True)
        objects = [row for row in yaml.safe_load_all(result.stdout) if row]
        project = next(row for row in objects if row['kind'] == 'AppProject' and row['metadata']['name'] == 'cloudlab-admission')
        self.assertEqual(project['spec']['destinations'], [{'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-policy'}])
        self.assertFalse(any(row.get('kind') == '*' for row in project['spec']['clusterResourceWhitelist']))
        for row in objects:
            if row['kind'] == 'Application' and row['spec']['project'] == 'cloudlab-admission':
                self.assertEqual(row['spec']['source']['repoURL'], project['spec']['sourceRepos'][0])
                self.assertTrue(row['spec']['source']['helm']['skipTests'])
                self.assertFalse(row['spec']['syncPolicy']['automated']['prune'])
