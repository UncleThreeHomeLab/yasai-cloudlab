import unittest
import json
import subprocess
from pathlib import Path
import yaml
from render import payload, images


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = payload()

    def test_private_api_and_no_implicit_role(self):
        objects = {x['metadata']['name']: x for x in self.data['operator'] if x['kind'] == 'ConfigMap'}
        self.assertEqual(objects['argocd-cm']['data']['admin.enabled'], 'false')
        self.assertEqual(objects['argocd-cm']['data']['users.anonymous.enabled'], 'false')
        self.assertEqual(objects['argocd-rbac-cm']['data']['policy.default'], 'role:no-access')
        self.assertTrue(all('@sha256:' in x for x in images(self.data['operator'])))

    def test_actual_enabled_public_root_renders_without_private_identity_injection(self):
        project = next(obj for obj in self.data['roots'] if obj['kind'] == 'AppProject' and obj['metadata']['name'] == 'cloudlab-previews')
        self.assertEqual(project['spec']['sourceRepos'], [self.data['repository']])
        self.assertFalse(any(obj['kind'] == 'ExternalSecret' and obj['metadata']['name'] == 'cloudlab-previews-source' for obj in self.data['roots']))
        self.assertFalse(any(obj['kind'] == 'Application' and obj['metadata']['name'] == 'cloudlab-services' for obj in self.data['roots']))

    def root_with(self, values, *, success=True):
        root = Path(__file__).resolve().parents[4]
        result = subprocess.run(['helm', 'template', 'root', str(root / 'gitops/roots/public'), '-f', '-'],
                                input=json.dumps(values), capture_output=True, text=True, timeout=60)
        if not success:
            self.assertNotEqual(result.returncode, 0)
            return []
        self.assertEqual(result.returncode, 0, result.stderr)
        return [obj for obj in yaml.safe_load_all(result.stdout) if obj]

    def test_present_empty_private_binding_is_invalid_but_absent_binding_is_safe(self):
        values = {'identity': {'enabled': True}, 'services': {'enabled': True, 'revision': 'a' * 40}}
        self.assertFalse(any(obj['kind'] == 'Application' and obj['metadata']['name'] == 'cloudlab-services'
                             for obj in self.root_with(values)))
        for binding in ({}, None, False):
            with self.subTest(binding=binding):
                values['identity']['argo'] = binding
                self.root_with(values, success=False)

    def test_services_application_uses_reviewed_pin_and_existing_private_binding(self):
        values = {'repository': 'https://github.com/example/platform.git', 'revision': 'main',
                  'identity': {'enabled': True, 'argo': {'valuesRepository': 'https://github.com/example/private.git',
                                                       'valuesRevision': 'b' * 40}},
                  'services': {'enabled': True, 'revision': 'a' * 40}}
        for pin in ('a' * 40, 'c' * 40):
            values['services']['revision'] = pin
            app = next(obj for obj in self.root_with(values) if obj['kind'] == 'Application' and
                       obj['metadata']['name'] == 'cloudlab-services')
            self.assertEqual(app['spec']['sources'][0]['targetRevision'], pin)
            self.assertEqual(app['spec']['sources'][0]['helm']['valuesObject']['revision'], pin)
            self.assertEqual(app['spec']['sources'][0]['helm']['valueFiles'],
                             ['$values/services/catalog.json', '$values/identity/argo-values.yaml'])
            self.assertEqual(app['spec']['sources'][1],
                             {'repoURL': values['identity']['argo']['valuesRepository'], 'targetRevision': 'main', 'ref': 'values'})
            self.assertFalse(app['spec']['syncPolicy']['automated']['prune'])
            self.assertNotIn('finalizers', app['metadata'])
        values['services']['revision'] = 'main'
        self.root_with(values, success=False)
        values['services']['revision'] = None
        self.root_with(values, success=False)
        values['services']['enabled'] = False
        self.assertFalse(any(obj['kind'] == 'Application' and obj['metadata']['name'] == 'cloudlab-services'
                             for obj in self.root_with(values)))
        values['services'] = {'enabled': True, 'revision': 'a' * 40}
        values['identity']['argo']['valuesRevision'] = 'main'
        self.root_with(values, success=False)

    def test_public_project_cannot_create_privileged_platform_objects(self):
        project = next(x['spec'] for x in self.data['roots'] if x['kind'] == 'AppProject' and x['metadata']['name'] == 'cloudlab-public')
        self.assertEqual(project['clusterResourceWhitelist'], [])
        self.assertEqual([x['namespace'] for x in project['destinations']], ['cloudlab-public'])
        denied = {'Secret', 'RoleBinding', 'Application', 'AppProject', 'ExternalSecret', 'Gateway'}
        self.assertFalse(denied & {x['kind'] for x in project['namespaceResourceWhitelist']})
        self.assertFalse(any('*' in x for x in project['sourceRepos']))

    def test_source_failure_or_application_removal_cannot_prune(self):
        controller = next(x for x in self.data['operator'] if x['kind'] == 'Deployment' and x['metadata']['name'] == 'argocd-applicationset-controller')
        self.assertIn('--policy=create-update', controller['spec']['template']['spec']['containers'][0]['args'])
        self.assertIn('--enable-policy-override=false', controller['spec']['template']['spec']['containers'][0]['args'])
        for app in [x for x in self.data['roots'] if x['kind'] == 'Application']:
            self.assertFalse(app['spec']['syncPolicy']['automated']['prune'])
            self.assertNotIn('finalizers', app['metadata'])
            self.assertIn('FailOnSharedResource=true', app['spec']['syncPolicy']['syncOptions'])

    def test_server_has_no_broad_chart_ingress_policy(self):
        policies = [x for x in self.data['operator'] if x['kind'] == 'NetworkPolicy']
        self.assertTrue(any(x['metadata']['name'] == 'argocd-default-deny' for x in policies))
        self.assertFalse(any(rule == {} for x in policies for rule in x['spec'].get('ingress', [])))

    def test_controller_go_memory_stays_below_its_container_limit(self):
        controller = next(x for x in self.data['operator'] if x['kind'] == 'StatefulSet')
        container = controller['spec']['template']['spec']['containers'][0]
        self.assertEqual(container['resources']['requests']['memory'], '512Mi')
        self.assertEqual(container['resources']['limits']['memory'], '2Gi')
        self.assertIn({'name': 'GOMEMLIMIT', 'value': '1600MiB'}, container['env'])
