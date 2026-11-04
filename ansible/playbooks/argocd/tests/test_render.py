import unittest
import json
import subprocess
from pathlib import Path
import yaml
from render import payload, images


class RenderTests(unittest.TestCase):
    def test_native_certificate_preparation_is_disabled_and_absent_binding_is_safe(self):
        for configuration, identity in (({'enabled': False}, {}), ({'enabled': True}, {}),
                ({'enabled': False}, {'argo': {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}})):
            objects = self.root_with({'certificates': {'configuration': configuration}, 'identity': identity})
            self.assertFalse(any(obj['kind'] == 'Application' and obj['metadata']['name'] == 'cloudlab-certificates' for obj in objects))
            self.assertFalse(any(obj['metadata']['name'] == 'cloudlab-certificates-source' for obj in objects))
            project = next(obj for obj in objects if obj['kind'] == 'AppProject' and obj['metadata']['name'] == 'cloudlab-certificates')
            self.assertEqual(project['spec']['sourceRepos'], ['https://github.com/UncleThreeHomeLab/yasai-cloudlab.git'])

    def test_native_certificate_sources_credentials_and_projects_remain_restricted(self):
        values = {'repository': 'https://github.com/example/platform.git', 'identity': {'argo': {
            'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}},
            'certificates': {'configuration': {'enabled': True, 'revision': 'a' * 40}}}
        objects = self.root_with(values)
        app = next(obj for obj in objects if obj['kind'] == 'Application' and obj['metadata']['name'] == 'cloudlab-certificates')
        self.assertEqual(app['spec']['sources'], [
            {'repoURL': values['repository'], 'targetRevision': 'a' * 40, 'path': 'platform/certificates/configuration',
             'helm': {'releaseName': 'cloudlab-certificates', 'valueFiles': ['$values/platform/certificates.yaml']}},
            {'repoURL': values['identity']['argo']['valuesRepository'], 'targetRevision': 'main', 'ref': 'values'}])
        self.assertFalse(app['spec']['syncPolicy']['automated']['prune'])
        self.assertNotIn('finalizers', app['metadata'])
        self.assertEqual(app['metadata']['annotations']['argocd.argoproj.io/skip-reconcile'], 'false')
        projects = {obj['metadata']['name']: obj['spec'] for obj in objects if obj['kind'] == 'AppProject'}
        self.assertEqual(projects['cloudlab-certificates']['sourceRepos'], [values['repository'], values['identity']['argo']['valuesRepository']])
        self.assertEqual(projects['cloudlab-cert-manager']['sourceRepos'], [values['repository']])
        self.assertEqual(projects['cloudlab-certificates']['namespaceResourceWhitelist'], [{'group': 'cert-manager.io', 'kind': 'Certificate'}])
        credential = next(obj for obj in objects if obj['kind'] == 'ExternalSecret' and obj['metadata']['name'] == 'cloudlab-certificates-source')
        self.assertEqual(credential['metadata']['annotations']['argocd.argoproj.io/sync-options'], 'Prune=false,Delete=false')
        target = credential['spec']['target']
        self.assertEqual((target['creationPolicy'], target['deletionPolicy']), ('Owner', 'Retain'))
        self.assertEqual(target['template']['data']['project'], 'cloudlab-certificates')
        self.assertEqual(target['template']['data']['url'], values['identity']['argo']['valuesRepository'])
        self.assertEqual(credential['spec']['dataFrom'], [{'extract': {'key': 'github-argocd'}}])
        self.assertFalse(any(obj['kind'] == 'Secret' for obj in objects))

    def test_native_certificate_configuration_rejects_bad_present_binding_pin_and_prerequisites(self):
        values = {'identity': {'argo': {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}},
                  'certificates': {'configuration': {'enabled': True, 'revision': 'a' * 40}}}
        for revision in ('main', None, 'short'):
            with self.subTest(revision=revision):
                self.root_with(values | {'certificates': {'configuration': {'enabled': True, 'revision': revision}}}, success=False)
        for binding in ({}, None, False, {'valuesRepository': values['identity']['argo']['valuesRepository'], 'valuesRevision': 'main'}):
            with self.subTest(binding=binding): self.root_with(values | {'identity': {'argo': binding}}, success=False)
        for field in ('enabled', 'reconcile'):
            for invalid in (False, 'false'):
                with self.subTest(field=field, invalid=invalid):
                    self.root_with(values | {'externalSecrets': {field: invalid}}, success=False)
        self.root_with({'certificates': {'configuration': {'enabled': 'false'}}}, success=False)

    def test_native_access_disabled_and_initial_unbound_root_preserve_legacy_owner(self):
        binding = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}
        for values in ({}, {'access': {'configuration': {'enabled': True}}}, {'identity': {'argo': binding}, 'access': {'configuration': {'enabled': False}}}):
            objects = self.root_with(values)
            self.assertFalse(any(o['kind'] == 'Application' and o['metadata']['name'] == 'cloudlab-access' for o in objects))
            self.assertFalse(any(o['metadata']['name'] == 'cloudlab-access-source' for o in objects))
            project = next(o for o in objects if o['kind'] == 'AppProject' and o['metadata']['name'] == 'cloudlab-access')
            self.assertEqual(project['spec']['sourceRepos'], ['https://github.com/UncleThreeHomeLab/yasai-cloudlab.git'])

    def test_native_access_uses_only_approved_private_revision_and_project_scoped_retained_reader(self):
        binding = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}
        values = {'identity': {'argo': binding}, 'access': {'configuration': {'enabled': True, 'revision': 'a' * 40}}}
        objects = self.root_with(values)
        app = next(o for o in objects if o['kind'] == 'Application' and o['metadata']['name'] == 'cloudlab-access')
        self.assertIsNone(app['spec']['source'])
        self.assertEqual(app['spec']['sources'], [
            {'repoURL': 'https://github.com/UncleThreeHomeLab/yasai-cloudlab.git', 'targetRevision': 'a' * 40,
             'path': 'platform/connectivity/access', 'helm': {'releaseName': 'cloudlab-access', 'valueFiles': ['$values/platform/access.yaml']}},
            {'repoURL': binding['valuesRepository'], 'targetRevision': 'b' * 40, 'ref': 'values'}])
        self.assertFalse(app['spec']['syncPolicy']['automated']['prune'])
        self.assertNotIn('finalizers', app['metadata'])
        baseline = self.root_with({'identity': {'argo': binding}, 'access': {'configuration': {'enabled': False}}})
        for name in ('cloudlab-tailscale-operator', 'cloudlab-access'):
            project = next(o['spec'] for o in objects if o['kind'] == 'AppProject' and o['metadata']['name'] == name)
            old = next(o['spec'] for o in baseline if o['kind'] == 'AppProject' and o['metadata']['name'] == name)
            self.assertEqual(project | {'sourceRepos': old['sourceRepos']}, old)
            self.assertEqual(project['sourceRepos'], old['sourceRepos'] + ([binding['valuesRepository']] if name == 'cloudlab-access' else []))
        reader = next(o for o in objects if o['metadata']['name'] == 'cloudlab-access-source')
        self.assertEqual(reader['metadata']['annotations']['argocd.argoproj.io/sync-options'], 'Prune=false,Delete=false')
        target = reader['spec']['target']
        self.assertEqual((target['creationPolicy'], target['deletionPolicy']), ('Owner', 'Retain'))
        self.assertEqual(target['template']['data']['project'], 'cloudlab-access')
        self.assertEqual(target['template']['data']['url'], binding['valuesRepository'])
        self.assertEqual(reader['spec']['dataFrom'], [{'extract': {'key': 'github-argocd'}}])

    def test_native_access_bad_present_binding_pin_and_prerequisites_fail_closed(self):
        binding = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}
        values = {'identity': {'argo': binding}, 'access': {'configuration': {'enabled': True, 'revision': 'a' * 40}}}
        for bad in ({}, None, False, binding | {'valuesRevision': 'main'}):
            self.root_with(values | {'identity': {'argo': bad}}, success=False)
        for pin in ('main', '', 'a' * 39):
            self.root_with(values | {'access': {'configuration': {'enabled': True, 'revision': pin}}}, success=False)
        for field in ('enabled', 'reconcile'):
            self.root_with(values | {'externalSecrets': {field: False}}, success=False)

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

    def test_private_catalog_requires_boolean_enablement_binding_pin_and_prerequisites(self):
        values = {'privateSources': {'enabled': True}}
        self.assertFalse(any(obj['metadata']['name'] == 'cloudlab-private-sources' for obj in self.root_with(values)))
        for enabled in ('false', 'true', 0, None):
            with self.subTest(enabled=enabled): self.root_with({'privateSources': {'enabled': enabled}}, success=False)
        values['identity'] = {'enabled': True, 'argo': {'valuesRepository': 'https://github.com/example/private.git',
                                                      'valuesRevision': 'b' * 40}}
        values['privateSources']['revision'] = 'c' * 40
        app = next(obj for obj in self.root_with(values) if obj['kind'] == 'Application' and obj['metadata']['name'] == 'cloudlab-private-sources')
        self.assertEqual(app['spec']['sources'][0]['targetRevision'], 'c' * 40)
        self.assertEqual(app['spec']['sources'][0]['helm']['valueFiles'], ['$values/platform/sources.yaml'])
        self.assertNotIn('ignoreMissingValueFiles', app['spec']['sources'][0]['helm'])
        self.assertEqual(app['spec']['syncPolicy']['automated'], {'enabled': True, 'prune': True, 'selfHeal': True, 'allowEmpty': True})
        self.assertIn('PruneLast=true', app['spec']['syncPolicy']['syncOptions'])
        self.assertNotIn('finalizers', app['metadata'])
        for field in ('admission', 'externalSecrets'):
            with self.subTest(field=field): self.root_with(values | {field: {'enabled': False}}, success=False)
        values['privateSources']['revision'] = 'main'
        self.root_with(values, success=False)

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
