import copy
import unittest

from automation.services.contract import validate, render, identity_request, external_route
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
        appset = objects[-1]['spec']['template']['spec']
        self.assertEqual(appset['project'], 'synthetic')
        self.assertEqual(appset['destination'], {'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-app-synthetic'})
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


if __name__ == '__main__':
    unittest.main()
