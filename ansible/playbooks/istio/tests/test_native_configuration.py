"""Native mesh ownership and Argo routing fail closed before Application writes."""
import copy
import unittest

import yaml

from playbooks.istio.tests.fixtures import COMPONENT, native_application, retained, run_native


class NativeConfigurationTests(unittest.TestCase):
    def test_native_gateway_application_preserves_values_branch_uid_and_no_prune(self):
        result, value = native_application()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(value['metadata']['uid'], 'retained-application')
        self.assertEqual(value['spec']['source']['targetRevision'], 'main')
        self.assertEqual(value['spec']['source']['helm']['valueFiles'], ['values.json'])
        self.assertEqual(value['spec']['source']['helm']['valuesObject'], {'zone': 'example.invalid',
            'argo': {'public': 'console.example.invalid', 'private': 'cd.internal.example.invalid'}})
        self.assertFalse(value['spec']['syncPolicy']['automated']['prune'])

    def test_initial_preparation_can_resume_without_adopting_an_application(self):
        values = retained()
        values['mesh_native_state'].pop('application_uid')
        values['mesh_native_state']['phase'] = 'preparing'
        values['mesh_native_current'] = {}
        values['mesh_native_checkpoint']['stat']['exists'] = False
        values['mesh_argo_routes'] = {}
        result, value = native_application(values)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('uid', value['metadata'])
        self.assertEqual(value['spec']['source']['helm']['valuesObject'], {'zone': 'example.invalid'})

    def test_changed_checkpoint_trust_or_application_ownership_never_reaches_render(self):
        for field in ('receipt', 'missing-app', 'zone', 'crd', 'component', 'ca', 'uid',
                      'owner', 'finalizer', 'parent', 'project', 'namespace', 'repository', 'path'):
            values = retained()
            current, state = values['mesh_native_current'], values['mesh_native_state']
            if field == 'receipt': values['mesh_native_checkpoint']['stat']['exists'] = False
            elif field == 'missing-app': values['mesh_native_current'] = {}
            elif field == 'zone': state['zone_hash'] = 'foreign'
            elif field == 'crd': state['gateway_api'] = {'foreign': 'replaced'}
            elif field == 'component': state['components'] = {'foreign': 'replaced'}
            elif field == 'ca': state['workload_ca']['content'] = 'd' * 64
            elif field == 'uid': state['application_uid'] = 'replaced'
            elif field == 'owner': current['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            elif field == 'finalizer': current['metadata']['finalizers'] = ['foreign']
            elif field == 'parent': current['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
            elif field == 'project': current['spec']['project'] = 'foreign'
            elif field == 'namespace': current['spec']['destination']['namespace'] = 'foreign'
            elif field == 'repository': current['spec']['source']['repoURL'] = 'https://github.com/fixture/foreign.git'
            else: current['spec']['source']['path'] = 'foreign'
            with self.subTest(field=field):
                result, value = native_application(values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(value)

    def argo_inputs(self):
        return {'mesh_native_zone': 'example.invalid', 'mesh_native_current': {},
            'mesh_argo_configmap': {'resources': [{'metadata': {'annotations': {
                'argocd.argoproj.io/tracking-id': 'cloudlab-argocd:/ConfigMap:argocd/argocd-cm'}}, 'data': {
                'oidc.config': 'issuer: https://login.example.invalid/realms/platform\nclientID: argocd',
                'url': 'https://console.example.invalid', 'additionalUrls': '[https://cd.internal.example.invalid]'}}]}}

    def argo(self, values):
        tasks = yaml.safe_load((COMPONENT / 'tasks/native-argo.yml').read_text())[1:]
        for task in tasks:
            for child in task.get('block', []):
                if 'ansible.builtin.include_tasks' in child:
                    child['ansible.builtin.include_tasks'] = str(COMPONENT / 'tasks/native-argo-origin.yml')
        tasks.append({'ansible.builtin.copy': {'dest': '{{ fixture_output_path }}', 'mode': '0600',
            'content': '{{ mesh_argo_routes | to_json }}'}})
        return run_native(tasks, values)

    def test_native_argo_origins_preserve_both_retained_exposures(self):
        result, value = self.argo(self.argo_inputs())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(value, {'public': 'console.example.invalid', 'private': 'cd.internal.example.invalid'})

    def test_omitted_oidc_keeps_an_initial_installation_without_argo_routes(self):
        values = self.argo_inputs()
        values['mesh_argo_configmap']['resources'][0]['data'].pop('oidc.config')
        result, value = self.argo(values)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(value, {})

    def test_gateway_api_native_checks_never_persist_and_refuse_wrong_owners_or_versions(self):
        source = yaml.safe_load((COMPONENT / 'tasks/native-gateway-api.yml').read_text())
        dry_run = next(task for task in source if 'kubernetes.core.k8s' in task)
        self.assertIs(dry_run['check_mode'], True)
        self.assertIs(dry_run['kubernetes.core.k8s']['server_side_apply']['force_conflicts'], False)
        guard = next(task for task in source if task.get('name') == 'Require its retained upstream owner, version and served-version inventory')
        current = {'metadata': {'uid': 'retained-crd', 'annotations': {
            'meta.helm.sh/release-name': 'traefik-crd', 'gateway.networking.k8s.io/bundle-version': 'v1.6.1'}},
            'spec': {'versions': [{'name': 'v1'}]}}
        for change in ('current', 'owner', 'bundle', 'extra-version'):
            actual = copy.deepcopy(current)
            if change == 'owner': actual['metadata']['annotations']['meta.helm.sh/release-name'] = 'foreign'
            elif change == 'bundle': actual['metadata']['annotations']['gateway.networking.k8s.io/bundle-version'] = 'foreign'
            elif change == 'extra-version': actual['spec']['versions'].append({'name': 'v1beta1'})
            tasks = [copy.deepcopy(guard), {'ansible.builtin.copy': {'dest': '{{ fixture_output_path }}',
                'content': 'true', 'mode': '0600'}}]
            result, value = run_native(tasks, {'mesh_existing_crd': {'resources': [actual]},
                'mesh_expected_crd': {'spec': {'versions': [{'name': 'v1'}]}}})
            with self.subTest(change=change):
                self.assertEqual(result.returncode == 0, change == 'current', result.stdout + result.stderr)
                self.assertEqual(value, True if change == 'current' else None)

    def test_native_argo_routing_refuses_missing_oidc_and_foreign_or_ambiguous_origins(self):
        for field in ('owner', 'issuer', 'client', 'missing', 'duplicate', 'foreign', 'path', 'userinfo', 'whitespace'):
            values = self.argo_inputs()
            source = values['mesh_argo_configmap']['resources'][0]
            if field == 'owner': source['metadata']['annotations'] = {}
            elif field == 'issuer': source['data']['oidc.config'] = 'issuer: https://foreign.invalid/realms/platform\nclientID: argocd'
            elif field == 'client': source['data']['oidc.config'] = 'issuer: https://login.example.invalid/realms/platform\nclientID: foreign'
            elif field == 'missing':
                source['data'].pop('oidc.config')
                values['mesh_native_current'] = {'spec': {'source': {'helm': {'valuesObject': {'argo': {'public': 'retained'}}}}}}
            elif field == 'duplicate': source['data']['additionalUrls'] = '[https://other.example.invalid]'
            elif field == 'foreign': source['data']['url'] = 'https://foreign.invalid'
            elif field == 'path': source['data']['url'] += '/path'
            elif field == 'userinfo': source['data']['url'] = 'https://@console.example.invalid'
            else: source['data']['url'] += '\t'
            with self.subTest(field=field):
                result, value = self.argo(values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(value)
