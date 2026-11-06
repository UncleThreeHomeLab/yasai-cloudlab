import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

from playbooks.services.files.contract import validate, render, identity_request, external_route, exposure_bindings
from playbooks.services.files.gitops import resources
from playbooks.services.tests.fixtures import definition, approval


class ContractTests(unittest.TestCase):
    def test_identity_reference_binds_approved_coordinates_without_copying_settings(self):
        from playbooks.services.files.contract import identity_binding
        value, allowed = definition(), approval()
        value['oidc'] = {'enabled': True, 'clientReference': 'synthetic'}
        allowed['identityClient'] = {'realm': 'applications', 'client': 'synthetic'}
        self.assertEqual(identity_binding(validate(value), allowed), allowed['identityClient'])
        self.assertFalse(any(row['kind'] == 'ExternalSecret' for row in
            resources(value, allowed, 'https://github.com/example/platform.git', 'b' * 40)))
        with self.assertRaisesRegex(ValueError, 'private Git'): identity_request(value, {})
        value['oidc']['secretReference'] = 'synthetic-oidc'
        value['secrets'] = [{'name': 'synthetic-oidc', 'mountPath': '/secrets/oidc'}]
        allowed['secretReferences'] = ['synthetic-oidc']
        allowed['identityClient']['secretReference'] = 'synthetic-oidc'
        objects = resources(value, allowed, 'https://github.com/example/platform.git', 'b' * 40)
        secret = next(row for row in objects if row['kind'] == 'ExternalSecret')
        self.assertEqual(secret['spec']['target']['deletionPolicy'], 'Retain')
        self.assertIn('"applications"', secret['spec']['target']['template']['data']['client_secret'])
        for mutate in (lambda a: a['identityClient'].update(client='foreign'),
                       lambda a: a.update(identityClient={}), lambda a: a.update(secretReferences=[]),
                       lambda a: a.update(chartPath='apps/notes'), lambda a: a.update(composition={})):
            denied = copy.deepcopy(allowed); mutate(denied)
            with self.assertRaises(ValueError): resources(value, denied, 'https://github.com/example/platform.git', 'b' * 40)
        mixed = copy.deepcopy(value); mixed['oidc']['audience'] = 'synthetic'
        with self.assertRaises(ValueError): validate(mixed)
        for publication in ('ready', 'retired'):
            denied = copy.deepcopy(allowed); denied['identityClient']['client'] = 'foreign'
            with self.assertRaises(ValueError):
                resources(value, denied, 'https://github.com/example/platform.git', 'b' * 40, publication=publication)
        with self.assertRaises(ValueError):
            resources(definition(), allowed, 'https://github.com/example/platform.git', 'b' * 40)

    def test_confidential_oidc_extracts_item_and_delivers_only_scoped_client_secret(self):
        value = definition()
        value['exposure'] = {'class': 'private', 'access': 'tailnet',
                             'hostname': 'synthetic.internal.example.invalid', 'path': '/', 'port': 8080}
        value['oidc'] = {'enabled': True, 'realm': 'applications', 'client': 'synthetic', 'public': False,
                         'audience': 'synthetic', 'scopes': ['profile'], 'callbackPaths': ['/oauth/callback'],
                         'roleMapping': {'viewer': ['viewer']}, 'secretReference': 'synthetic-oidc'}
        value['secrets'] = [{'name': 'synthetic-oidc', 'mountPath': '/secrets/oidc'}]
        approved = approval()
        approved['secretReferences'] = ['synthetic-oidc']
        objects = resources(value, approved, 'https://github.com/example/platform.git', 'b' * 40)
        secret = next(row for row in objects if row['kind'] == 'ExternalSecret' and row['metadata']['name'] == 'synthetic-oidc')
        spec = secret['spec']
        self.assertEqual(spec['dataFrom'], [{'extract': {'key': 'keycloak-client-secrets'}}])
        self.assertEqual(spec['refreshInterval'], '24h')
        self.assertEqual(spec['secretStoreRef'], {'name': 'cloudlab', 'kind': 'ClusterSecretStore'})
        self.assertEqual(spec['target']['name'], 'synthetic-oidc')
        self.assertEqual(spec['target']['creationPolicy'], 'Owner')
        self.assertEqual(spec['target']['deletionPolicy'], 'Retain')
        template = spec['target']['template']
        self.assertEqual(template['engineVersion'], 'v2')
        self.assertEqual(template['mergePolicy'], 'Replace')
        self.assertEqual(set(template['data']), {'client_secret'})
        self.assertIn('"applications"', template['data']['client_secret'])
        self.assertIn('"synthetic"', template['data']['client_secret'])
        with tempfile.TemporaryDirectory() as temporary:
            chart = Path(temporary)
            (chart / 'Chart.yaml').write_text('apiVersion: v2\nname: oidc-secret-check\nversion: 0.0.0\n')
            (chart / 'templates').mkdir()
            (chart / 'templates/secret.yaml').write_text('apiVersion: v1\nkind: Secret\nmetadata: {name: synthetic}\nstringData:\n'
                '{{- range $key, $template := .Values.templates }}\n'
                '  {{ $key | quote }}: {{ tpl $template (merge (dict "Template" $.Template) $.Values.input) | quote }}\n'
                '{{- end }}\n')

            def evaluate(document):
                return subprocess.run(['helm', 'template', 'oidc-secret-check', str(chart), '-f', '-'],
                    input=yaml.safe_dump({'templates': template['data'], 'input': {'client_secrets': document}}),
                    capture_output=True, text=True, timeout=30)

            credential = '0\nsynthetic-value\n'
            source = {'applications': {'synthetic': credential, 'unrelated': 'must-not-copy'},
                      'platform': {'synthetic': 'must-not-copy'}}
            valid = evaluate(json.dumps(source))
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertEqual(yaml.safe_load(valid.stdout)['stringData'], {'client_secret': credential})
            invalid = [('missing', {'applications': {}}), ('missing-realm', {'platform': source['platform']}),
                       ('malformed-json', '{')]
            invalid += [(type(selected).__name__, {'applications': {'synthetic': selected}})
                        for selected in ('', None, 1, True, {'unrelated': 'must-not-copy'}, ['must-not-copy'])]
            for name, document in invalid:
                with self.subTest(credential=name):
                    rejected = evaluate(document if isinstance(document, str) else json.dumps(document))
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertEqual(rejected.stdout, '')
                    self.assertNotIn('must-not-copy', rejected.stderr)
                    if name not in ('missing-realm', 'malformed-json'):
                        self.assertIn('Required OIDC client secret must be a nonempty string', rejected.stderr)

        with self.assertRaisesRegex(ValueError, 'unapproved or privileged credentials'):
            resources(value, dict(approved, secretReferences=[]), 'https://github.com/example/platform.git', 'b' * 40)
        public = copy.deepcopy(value)
        public['oidc']['public'] = True
        public['oidc'].pop('secretReference')
        public['secrets'] = []
        self.assertFalse(any(row['kind'] == 'ExternalSecret' for row in
            resources(public, approved, 'https://github.com/example/platform.git', 'b' * 40)))

    def test_minimal_and_persistent_render_has_no_platform_or_secret_owner(self):
        value = definition()
        for persistent in (False, True):
            value['persistence']['enabled'] = persistent
            objects = render(validate(value))
            self.assertEqual({o['kind'] for o in objects},
                             {'Deployment', 'ServiceAccount', 'Service'} | ({'PersistentVolumeClaim'} if persistent else set()))
            if persistent:
                deployment = next(o for o in objects if o['kind'] == 'Deployment')
                self.assertEqual(deployment['spec']['strategy'], {'type': 'Recreate'})
                claim = next(o for o in objects if o['kind'] == 'PersistentVolumeClaim')
                self.assertEqual(claim['metadata']['annotations']['argocd.argoproj.io/sync-options'], 'Prune=false,Delete=false')

    def test_invalid_definitions_fail(self):
        base = definition()
        mutations = [lambda v: v.update(project='default'), lambda v: v.update(destination='other'),
                     lambda v: v.update(name='default'),
                     lambda v: v.update(image='python:latest'), lambda v: v.update(owner=''),
                     lambda v: v['resources']['requests'].update(cpu='300m'),
                     lambda v: v['health']['readiness'].update(port='undeclared'),
                     lambda v: v['persistence'].update(retention='delete'),
                     lambda v: v['monitoring'].update(enabled=True),
                     lambda v: v['rollouts'].update(enabled=True),
                     lambda v: v['ports'].append(copy.deepcopy(v['ports'][0]))]
        for mutate in mutations:
            value = copy.deepcopy(base)
            mutate(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate(value)

    def test_budget_reserves_one_pod_for_a_stateless_rollout(self):
        value = definition()
        value['replicas'] = 3
        value['resources']['limits']['cpu'] = '600m'
        with self.assertRaisesRegex(ValueError, 'namespace resource budget'): validate(value)

    def test_additional_exposure_is_private_and_part_of_migration_identity(self):
        value = definition()
        value['exposure'] = {'class': 'public', 'hostname': 'service.example.invalid',
                             'access': 'public', 'path': '/', 'port': 8080}
        value['additionalExposures'] = [{'class': 'private', 'hostname': 'ops.internal.example.invalid',
                                       'access': 'tailnet', 'path': '/', 'port': 8080}]
        validate(value)
        before = exposure_bindings(value)
        value['additionalExposures'][0]['hostname'] = 'different.internal.example.invalid'
        self.assertNotEqual(before, exposure_bindings(value))
        value['additionalExposures'][0].update({'class': 'public', 'access': 'public'})
        with self.assertRaises(ValueError): validate(value)

    def test_single_exposure_supplies_callback_route_and_external_hostname(self):
        value = definition()
        value['exposure'] = {'class': 'public', 'hostname': 'notes.example.invalid', 'access': 'public', 'path': '/', 'port': 8080}
        value['oidc'] = {'enabled': True, 'realm': 'applications', 'client': 'notes-web', 'public': True,
                         'audience': 'notes-api', 'callbackPaths': ['/callback'], 'scopes': ['profile'],
                         'roleMapping': {'reader': ['viewer']}}
        validate(value)
        route = next(o for o in render(value) if o['kind'] == 'HTTPRoute')
        self.assertEqual(route['spec']['hostnames'], [external_route(value, 'https://origin.example.invalid')['hostname']])
        self.assertEqual(identity_request(value, {})['client']['callbacks'], ['https://notes.example.invalid/callback'])
        value['oidc']['callbackPaths'] = ['/*']
        with self.assertRaises(ValueError): validate(value)

    def test_admin_destinations_and_credentials_cannot_be_selected_by_author(self):
        value, allowed = definition(), approval()
        objects = resources(value, allowed, 'https://github.com/example/platform.git', 'b' * 40)
        appset = next(obj for obj in objects if obj['kind'] == 'ApplicationSet')['spec']['template']['spec']
        self.assertEqual(appset['project'], 'synthetic')
        self.assertEqual(appset['destination'], {'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-app-synthetic'})
        self.assertEqual(appset['sources'][0]['helm']['valuesObject'], dict(value, routeOnly=False, routeBackends={}))
        policy = next(obj for obj in objects if obj['kind'] == 'AuthorizationPolicy')
        self.assertEqual(policy['spec']['rules'][0]['from'][0]['source']['principals'],
                         ['cluster.local/ns/cloudlab-app-synthetic/sa/synthetic'])
        project = next(obj for obj in objects if obj['kind'] == 'AppProject')
        self.assertNotIn({'group': 'security.istio.io', 'kind': 'AuthorizationPolicy'},
                         project['spec']['namespaceResourceWhitelist'])
        for key, changed in [('namespace', 'argocd'), ('revision', 'main'), ('valuesPath', '../values.yaml')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                resources(value, dict(allowed, **{key: changed}), 'https://github.com/example/platform.git', 'b' * 40)
        value['secrets'] = [{'name': 'seaweedfs-admin', 'mountPath': '/secrets/admin'}]
        with self.assertRaises(ValueError): resources(value, allowed, 'https://github.com/example/platform.git', 'b' * 40)

    def test_source_visibility_and_network_exposure_are_independent(self):
        for visibility in ('public', 'private'):
            for exposure in ('public', 'private'):
                value, allowed = definition(), dict(approval(), visibility=visibility)
                value['exposure'] = {'class': exposure, 'hostname': 'service.' + ('internal.' if exposure == 'private' else '') + 'example.invalid',
                                     'access': 'public' if exposure == 'public' else 'tailnet', 'path': '/', 'port': 8080}
                objects = resources(value, allowed, 'https://github.com/example/platform.git', 'b' * 40)
                namespace = next(o for o in objects if o['kind'] == 'Namespace')
                self.assertEqual(namespace['metadata']['labels']['cloudlab.io/gateway'], exposure)
                self.assertEqual(any(o['kind'] == 'ExternalSecret' for o in objects), visibility == 'private')

    def test_same_repository_uses_complete_definition_without_conflicting_value_revision(self):
        value = definition()
        repository = 'https://github.com/example/platform.git'
        allowed = dict(approval(), repository=repository, revision='a' * 40)
        objects = resources(value, allowed, repository, 'b' * 40)
        spec = next(o for o in objects if o['kind'] == 'ApplicationSet')['spec']['template']['spec']
        self.assertNotIn('sources', spec)
        self.assertEqual(spec['source']['targetRevision'], 'b' * 40)
        self.assertEqual(spec['source']['helm'], {'valuesObject': dict(value, routeOnly=False, routeBackends={})})
        allowed['repository'] = 'https://github.com/example/other.git'
        objects = resources(value, allowed, repository, 'b' * 40)
        sources = next(o for o in objects if o['kind'] == 'ApplicationSet')['spec']['template']['spec']['sources']
        self.assertEqual(len(sources), 2)
        self.assertEqual(sources[1]['targetRevision'], 'a' * 40)
        self.assertEqual(sources[0]['helm']['valuesObject'], dict(value, routeOnly=False, routeBackends={}))


if __name__ == '__main__':
    unittest.main()
