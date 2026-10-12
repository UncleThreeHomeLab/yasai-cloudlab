import copy
import unittest

from automation.services.contract import validate, render, identity_request, external_route, exposure_bindings
from automation.services.gitops import resources
from automation.services.tests.fixtures import definition, approval


class ContractTests(unittest.TestCase):
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
        self.assertEqual(appset['sources'][0]['helm']['valuesObject'], value)
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
        self.assertEqual(spec['source']['helm'], {'valuesObject': value})
        allowed['repository'] = 'https://github.com/example/other.git'
        objects = resources(value, allowed, repository, 'b' * 40)
        sources = next(o for o in objects if o['kind'] == 'ApplicationSet')['spec']['template']['spec']['sources']
        self.assertEqual(len(sources), 2)
        self.assertEqual(sources[1]['targetRevision'], 'a' * 40)
        self.assertEqual(sources[0]['helm']['valuesObject'], value)


if __name__ == '__main__':
    unittest.main()
