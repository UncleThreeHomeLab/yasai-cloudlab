"""Reviewed compositions retain exact source, privilege and release authority."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from playbooks.services.files.compositions import validate, DEFAULT_TOLERATIONS
from playbooks.services.files.compositions import backend
from playbooks.services.files.gitops import resources
from playbooks.services.tests.fixtures import definition, approval as ordinary_approval, composition_approval, composition_definition


class CompositionTests(unittest.TestCase):
    def render(self, approval=None):
        return resources(composition_definition(), approval or composition_approval(),
                         'https://github.com/example/platform.git', 'd' * 40)

    def test_separate_pinned_sources_scoped_projects_and_namespace_network_budget(self):
        objects = self.render()
        project = next(row for row in objects if row['kind'] == 'AppProject' and row['metadata']['name'] == 'synthetic')
        self.assertFalse(project['spec']['clusterResourceWhitelist'])
        self.assertFalse({'Secret', 'ExternalSecret', 'Policy', 'ValidatingPolicy'} & {
            row['kind'] for row in project['spec']['namespaceResourceWhitelist']})
        app = next(row for row in objects if row['kind'] == 'ApplicationSet' and row['metadata']['name'] == 'synthetic')
        sources = app['spec']['template']['spec']['sources']
        self.assertEqual(len(sources), 3)
        self.assertEqual(sources[1]['targetRevision'], 'c' * 40)
        self.assertEqual(sources[1]['path'], 'deploy/helm/application')
        self.assertTrue(sources[0]['helm']['valuesObject']['routeOnly'])
        self.assertEqual(sources[0]['helm']['valuesObject']['routeBackends']['web.internal.example.invalid']['service'], 'web')
        self.assertTrue(any(row['metadata']['name'] == 'platform-deny' and row['spec']['ingress'] == []
                            for row in objects if row['kind'] == 'NetworkPolicy'))
        profile_project = next(row for row in objects if row['kind'] == 'AppProject' and row['metadata']['name'] == 'synthetic-profile')
        self.assertEqual(profile_project['spec']['destinations'][0]['namespace'], 'cloudlab-policy')
        self.assertEqual(profile_project['spec']['namespaceResourceWhitelist'], [{'group': '', 'kind': 'ConfigMap'}])

    def test_rejects_unapproved_sources_privileges_claims_and_secret_scope(self):
        for change in ('source', 'token', 'host', 'privileged', 'capability', 'sysctl', 'volume', 'claim', 'secret', 'budget', 'host-port'):
            approval = composition_approval()
            value = approval['composition']
            spec = value['workloads'][0]['podSpec']
            if change == 'source': value['chart']['path'] = '../foreign'
            elif change == 'token': spec['automountServiceAccountToken'] = True
            elif change == 'host': spec['hostNetwork'] = True
            elif change == 'privileged': spec['containers'][0]['securityContext']['privileged'] = True
            elif change == 'capability': spec['containers'][0]['securityContext']['capabilities']['add'] = ['SYS_ADMIN']
            elif change == 'sysctl': spec['securityContext']['sysctls'] = [{'name': 'net.ipv4.ip_forward', 'value': '1'}]
            elif change == 'volume': spec['volumes'] = [{'name': 'host', 'hostPath': {'path': '/'}}]
            elif change == 'claim': spec['volumes'] = [{'name': 'foreign', 'persistentVolumeClaim': {'claimName': 'foreign'}}]
            elif change == 'secret': value['secrets'] = [{'name': 'foreign', 'item': 'admin', 'fields': {'password': 'password'}}]
            elif change == 'budget': value['budget']['requests.cpu'] = '1m'
            elif change == 'host-port': spec['containers'][0]['ports'] = [{'containerPort': 8080, 'hostPort': 8080}]
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate(approval)

    def test_routing_controls_are_catalog_owned_and_override_conflicting_external_values(self):
        from playbooks.services.files.contract import validate as service_definition
        value = composition_definition()
        objects = resources(value, ordinary_approval(), 'https://github.com/example/platform.git', 'd' * 40)
        app = next(row for row in objects if row['kind'] == 'ApplicationSet')
        owned = app['spec']['template']['spec']['sources'][0]['helm']['valuesObject']
        self.assertIs(owned['routeOnly'], False)
        self.assertEqual(owned['routeBackends'], {})
        conflict = {'routeOnly': True, 'routeBackends': {value['exposure']['hostname']: {
            'service': 'foreign', 'port': 9999, 'selector': {'untrusted': 'yes'}}}}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'external.yaml').write_text(yaml.safe_dump(conflict))
            (directory / 'owned.yaml').write_text(yaml.safe_dump(owned))
            result = subprocess.run(['helm', 'template', 'ordinary', 'charts/service',
                '-f', str(directory / 'external.yaml'), '-f', str(directory / 'owned.yaml')],
                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = [row for row in yaml.safe_load_all(result.stdout) if row]
        self.assertEqual(len([row for row in actual if row['kind'] == 'Deployment']), 1)
        route = next(row for row in actual if row['kind'] == 'HTTPRoute')
        self.assertEqual(route['spec']['rules'][0]['backendRefs'], [{'name': value['name'], 'port': value['exposure']['port']}])
        for key, setting in (('routeOnly', False), ('routeBackends', {})):
            with self.subTest(key=key), self.assertRaises(ValueError): service_definition(dict(value, **{key: setting}))
        payload = {'repository': 'https://github.com/example/platform.git', 'revision': 'd' * 40,
                   'catalog': [{'definition': dict(value, routeOnly=True), 'approval': ordinary_approval()}]}
        result = subprocess.run(['helm', 'template', 'catalog', 'platform/delivery/services', '-f', '-'],
                                input=json.dumps(payload), capture_output=True, text=True, timeout=90)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Routing controls belong', result.stderr)

    def test_separate_private_listeners_keep_gateway_ports_and_backends_scoped(self):
        value, approval = definition(), composition_approval()
        value['ports'] = [{'name': 'http', 'port': 8080}]
        value['exposure'] = {'class': 'private', 'hostname': 'ui.internal.example.invalid',
                             'access': 'tailnet', 'path': '/', 'port': 8080}
        value['additionalExposures'] = [dict(value['exposure'], hostname='login.internal.example.invalid', port=8080)]
        approval['composition']['backends'] = {
            'ui.internal.example.invalid': {'service': 'web', 'port': 8080, 'selector': {'component': 'web'}},
            'login.internal.example.invalid': {'service': 'google', 'port': 8080, 'selector': {'component': 'google'},
                             'readiness': {'path': '/oauth/google/callback', 'statuses': [400]}}}
        objects = resources(value, approval, 'https://github.com/example/platform.git', 'd' * 40)
        network = [row for row in objects if row['kind'] == 'NetworkPolicy' and row['metadata']['name'] != 'platform-deny']
        self.assertEqual({row['spec']['podSelector']['matchLabels']['component'] for row in network}, {'web', 'google'})
        for row in network:
            expected = 8080
            self.assertEqual(row['spec']['ingress'][0]['ports'], [{'protocol': 'TCP', 'port': expected}, {'protocol': 'TCP', 'port': 15008}])
        gates = [row for row in objects if row['kind'] == 'AuthorizationPolicy' and row['metadata']['name'].startswith('platform-gateway-')]
        self.assertEqual({row['spec']['rules'][0]['to'][0]['operation']['ports'][0] for row in gates}, {'8080'})
        internal = next(row for row in objects if row['kind'] == 'AuthorizationPolicy' and row['metadata']['name'] == 'platform-workloads')
        self.assertNotIn('cloudlab-gateway', json.dumps(internal))
        application = next(row for row in objects if row['kind'] == 'ApplicationSet' and row['metadata']['name'] == 'synthetic')
        route_values = application['spec']['template']['spec']['sources'][0]['helm']['valuesObject']
        result = subprocess.run(['helm', 'template', 'routes', 'charts/service', '-f', '-'],
                                input=json.dumps(route_values), capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr)
        routes = [row for row in yaml.safe_load_all(result.stdout) if row]
        self.assertEqual({row['kind'] for row in routes}, {'HTTPRoute'})
        self.assertEqual({(row['spec']['rules'][0]['backendRefs'][0]['name'], row['spec']['rules'][0]['backendRefs'][0]['port'])
                          for row in routes}, {('web', 8080), ('google', 8080)})

    def test_listener_readiness_accepts_only_its_explicit_bounded_response(self):
        from playbooks.services.files.remote import inspect
        value, approval = composition_definition(), composition_approval()
        approval['composition']['backends'][value['exposure']['hostname']]['readiness'] = {
            'path': '/oauth/callback', 'statuses': [400]}
        route = {'metadata': {'generation': 1}, 'spec': {'hostnames': [value['exposure']['hostname']]},
                 'status': {'parents': [{'conditions': [{'type': kind, 'status': 'True', 'observedGeneration': 1}
                                                       for kind in ('Accepted', 'ResolvedRefs')]}]}}
        def get(kind, name=None, namespace=None):
            if kind.startswith('gateway.'):
                return {'metadata': {'generation': 1}, 'status': {'conditions': [
                    {'type': 'Programmed', 'status': 'True', 'observedGeneration': 1}]}}
            if kind.startswith('httproute.'): return route
            if kind == 'service': return {'spec': {'clusterIP': '10.43.0.1'}}
            raise AssertionError(kind)
        with patch('playbooks.services.files.remote.get', side_effect=get), \
                patch('playbooks.services.files.remote.direct_https', return_value=(400, b'')) as https:
            inspect({'action': 'tls', 'definition': value, 'approval': approval})
            self.assertEqual(https.call_args.args[0], 'https://' + value['exposure']['hostname'] + '/oauth/callback')
            for status in (200, 404, 502):
                https.return_value = status, b''
                with self.subTest(status=status), self.assertRaises(RuntimeError):
                    inspect({'action': 'tls', 'definition': value, 'approval': approval})
        value['exposure']['path'] = '/different'
        with self.assertRaises(ValueError): resources(value, approval, 'https://github.com/example/platform.git', 'd' * 40)

    def test_component_release_sources_and_aggregate_secret_stay_with_protected_owners(self):
        approval = composition_approval()
        approval['artifact'] = {'repository': 'registry.example.invalid/cloudlab-public/synthetic', 'project': 'cloudlab-public',
            'releasePath': 'apps/releases/synthetic.json', 'sourceRepository': 'example/application',
            'identities': ['https://github.com/example/application/.github/workflows/ci.yaml@refs/heads/main'],
            'action': 'Enforce', 'components': ['web', 'worker'], 'primaryComponent': 'web'}
        approval['secretReferences'] = ['application-credentials']
        approval['composition']['secrets'] = [{'name': 'application-credentials', 'item': 'application-credentials',
                                              'fields': {'api_token': 'api_token'}}]
        objects = self.render(approval)
        application = next(row for row in objects if row['kind'] == 'ApplicationSet' and row['metadata']['name'] == 'synthetic')
        values = application['spec']['template']['spec']['sources'][1]['helm']['valuesObject']
        self.assertEqual(values['imagePullSecrets'], [{'name': 'harbor-application-pull'}])
        self.assertEqual(values['images']['worker']['digest'], '{{ index .components "worker" }}')
        profile = next(row for row in objects if row['kind'] == 'ApplicationSet' and row['metadata']['name'] == 'synthetic-profile')
        self.assertEqual(profile['spec']['generators'], application['spec']['generators'])
        secret = next(row for row in objects if row['kind'] == 'ExternalSecret' and row['metadata']['name'] == 'application-credentials')
        self.assertEqual(secret['spec']['data'], [{'secretKey': 'api_token', 'remoteRef': {'key': 'application-credentials', 'property': 'api_token'}}])

    def test_backend_requires_each_component_and_its_protected_source(self):
        approval, value = composition_approval(), composition_definition()
        objects = self.render(approval)
        policy = next(row for row in objects if row['kind'] == 'ValidatingPolicy')
        policy['metadata']['generation'] = 1
        policy['status'] = {'conditionStatus': {'ready': True, 'conditions': [{'status': 'True', 'observedGeneration': 1}]}}
        application = copy.deepcopy(next(row for row in objects if row['kind'] == 'ApplicationSet' and row['metadata']['name'] == 'synthetic')['spec']['template'])
        profile = copy.deepcopy(next(row for row in objects if row['kind'] == 'ApplicationSet' and row['metadata']['name'] == 'synthetic-profile')['spec']['template'])
        for app in (application, profile): app['status'] = {'health': {'status': 'Healthy'}, 'sync': {'status': 'Synced'}}
        state = {'data': {'release.json': json.dumps({'approval': policy['metadata']['annotations']['cloudlab.io/composition-profile'],
                                                    'images': approval['composition']['images']})}}
        deployments = {row['name']: {'metadata': {'generation': 1}, 'status': {'observedGeneration': 1,
                            **{field: row['replicas'] for field in ('replicas', 'updatedReplicas', 'readyReplicas', 'availableReplicas')}},
                        'spec': {'replicas': row['replicas'], 'template': {'spec': copy.deepcopy(row['podSpec'])}}}
                       for row in approval['composition']['workloads']}
        def get(kind, name=None, namespace=None):
            if kind.startswith('application.'):
                return ({'spec': {'source': application['spec']['sources'][0]}} if name == 'cloudlab-services'
                        else profile if name == 'synthetic-profile' else application)
            if kind.startswith('validatingpolicy.'): return policy
            if kind == 'configmap': return state
            if kind == 'deployment': return deployments.get(name)
            if kind == 'resourcequota': return {'spec': {'hard': dict(approval['composition']['budget'],
                                                                     **{'limits.cpu': '1', 'limits.memory': '1Gi'})}}
            raise AssertionError(kind)
        backend(value, approval, get, None)
        for mutation in ('image', 'values', 'state', 'workload', 'capability', 'desired-count', 'updatedReplicas',
                         'readyReplicas', 'replicas', 'unavailableReplicas', 'terminatingReplicas', 'generation'):
            with self.subTest(mutation=mutation):
                saved = copy.deepcopy((application, state, deployments))
                if mutation == 'image': deployments['worker']['spec']['template']['spec']['containers'][0]['image'] = 'foreign'
                elif mutation == 'values': application['spec']['sources'][2]['targetRevision'] = 'e' * 40
                elif mutation == 'state': state['data']['release.json'] = '{}'
                elif mutation == 'capability': deployments['worker']['spec']['template']['spec']['containers'][0]['securityContext']['capabilities']['add'].append('NET_ADMIN')
                elif mutation == 'desired-count': deployments['worker']['spec']['replicas'] = 0
                elif mutation == 'generation': deployments['worker']['status']['observedGeneration'] = 0
                elif mutation in ('unavailableReplicas', 'terminatingReplicas'): deployments['worker']['status'][mutation] = 1
                elif mutation in ('updatedReplicas', 'readyReplicas'): deployments['worker']['status'][mutation] = 0
                elif mutation == 'replicas': deployments['worker']['status'][mutation] = 2
                else: del deployments['worker']
                with self.assertRaises(RuntimeError): backend(value, approval, get, None)
                application, state, deployments = saved

    def evaluate(self, changes=None, state_change=None, default_tolerations=None):
        approval = composition_approval()
        policy = next(row for row in self.render(approval) if row['kind'] == 'ValidatingPolicy')
        self.assertEqual(policy['spec']['failurePolicy'], 'Fail')
        expression = next(row['expression'] for row in policy['spec']['variables'] if row['name'] == 'profiles')
        profiles = json.loads(json.loads(expression[len('yaml.parse('):-1]))
        good = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'accepted', 'namespace': approval['namespace'],
                'ownerReferences': [{'apiVersion': 'apps/v1', 'kind': 'ReplicaSet', 'name': 'web-123', 'uid': 'synthetic', 'controller': True}]},
                'spec': profiles[0]['podSpec']}
        good['spec'].update(serviceAccount='default', priority=0, preemptionPolicy='PreemptLowerPriority',
                            tolerations=copy.deepcopy(default_tolerations if default_tolerations is not None else DEFAULT_TOLERATIONS[:2]))
        pods = [good]
        if changes:
            bad = copy.deepcopy(good)
            bad['metadata']['name'] = 'rejected'
            changes(bad)
            pods.append(bad)
        state = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'composition-synthetic', 'namespace': 'cloudlab-policy'},
                 'data': {'release.json': json.dumps({'approval': policy['metadata']['annotations']['cloudlab.io/composition-profile'],
                                                    'images': approval['composition']['images']})}}
        if state_change: state_change(state)
        unavailable = state['metadata']['name'] != 'composition-synthetic'
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            files = {'policy.yaml': policy, 'pods.yaml': pods,
                'values.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Values', 'namespaceSelector': [
                    {'name': approval['namespace'], 'labels': {'kubernetes.io/metadata.name': approval['namespace']}}]},
                'context.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Context', 'metadata': {'name': 'composition'},
                    'spec': {'resources': [state]}},
                'kyverno-test.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Test', 'metadata': {'name': 'composition'},
                    'policies': ['policy.yaml'], 'resources': ['pods.yaml'], 'variables': 'values.yaml', 'context': 'context.yaml',
                    'results': [{'isValidatingPolicy': True, 'kind': 'Pod', 'policy': policy['metadata']['name'],
                        'resources': [pod['metadata']['name']], 'result': 'error' if unavailable else 'pass' if pod is good and not state_change else 'fail'} for pod in pods]}}
            for name, value in files.items():
                (directory / name).write_text(yaml.safe_dump_all(value) if isinstance(value, list) else yaml.safe_dump(value))
            result = subprocess.run(['kyverno', 'test', str(directory)], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr)[-10000:])
        self.assertNotIn('error)', result.stdout)

    def test_native_policy_matches_complete_profile_and_denies_privilege_mutations(self):
        mutations = {
            'wrong-component': lambda pod: pod['spec']['containers'][0].update(image=composition_approval()['composition']['images']['worker']),
            'extra-capability': lambda pod: pod['spec']['containers'][0]['securityContext']['capabilities']['add'].append('NET_ADMIN'),
            'command': lambda pod: pod['spec']['containers'][0].update(command=['sh', '-c', 'unapproved']),
            'ephemeral': lambda pod: pod['spec'].update(ephemeralContainers=[{'name': 'debug', 'image': 'foreign'}]),
            'host': lambda pod: pod['spec'].update(hostPID=True),
            'forged-label': lambda pod: pod['metadata'].update(ownerReferences=[], labels={'component': 'worker'}),
            'extra-mount': lambda pod: pod['spec']['containers'][0].update(volumeMounts=[{'name': 'extra', 'mountPath': '/host'}]),
            'device-resource': lambda pod: pod['spec']['containers'][0]['resources']['limits'].update({'example.invalid/device': '1'}),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name): self.evaluate(mutation)
        self.evaluate(state_change=lambda state: state['data'].update({'release.json': json.dumps({'approval': 'stale', 'images': {}})}))

    def test_absent_protected_release_state_cannot_grant_a_pod_profile(self):
        self.evaluate(state_change=lambda state: state['metadata'].update(name='absent-profile'))

    def test_api_default_tolerations_only_accept_exact_literals(self):
        from playbooks.services.files.compositions import normalized_spec
        self.evaluate(default_tolerations=DEFAULT_TOLERATIONS)
        for name, mutate in (
                ('seconds', lambda rows: rows[0].update(tolerationSeconds=600)),
                ('broad', lambda rows: rows.append({'operator': 'Exists'})),
                ('foreign', lambda rows: rows.append({'key': 'dedicated', 'operator': 'Exists', 'effect': 'NoSchedule'})),
                ('duplicate', lambda rows: rows.append(copy.deepcopy(rows[0])))):
            with self.subTest(name=name):
                self.evaluate(lambda pod: mutate(pod['spec']['tolerations']))
                spec = copy.deepcopy(composition_approval()['composition']['workloads'][0]['podSpec'])
                spec['tolerations'] = copy.deepcopy(DEFAULT_TOLERATIONS[:2])
                mutate(spec['tolerations'])
                with self.assertRaises(ValueError): normalized_spec(spec)
        spec = copy.deepcopy(composition_approval()['composition']['workloads'][0]['podSpec'])
        self.assertEqual(normalized_spec(dict(spec, tolerations=DEFAULT_TOLERATIONS)), normalized_spec(spec))

    def test_namespace_privileges_wait_for_ready_generation_of_fail_closed_policy(self):
        from playbooks.admission.files.chart import render
        policy = next(row for row in render(True) if row['metadata']['name'] == 'cloudlab-composition-namespace')
        self.assertIn("resource.Get('policies.kyverno.io/v1', 'validatingpolicies'", policy['spec']['variables'][0]['expression'])
        # The CLI mapper lacks custom APIs; exercise the same native readiness predicate via a core context.
        policy['spec']['variables'][0]['expression'] = "yaml.parse(resource.Get('v1', 'configmaps', '', 'ready-policy').data['policy.json'])"
        for ready, generation in ((True, 2), (False, 2), (True, 1)):
            resource = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'cloudlab-app-synthetic', 'labels': {
                'cloudlab.io/composition': 'approved', 'cloudlab.io/owner': 'service-platform',
                'pod-security.kubernetes.io/enforce': 'privileged', 'pod-security.kubernetes.io/enforce-version': 'v1.36',
                'pod-security.kubernetes.io/audit': 'restricted', 'pod-security.kubernetes.io/warn': 'restricted'}}}
            context = {'apiVersion': 'policies.kyverno.io/v1', 'kind': 'ValidatingPolicy',
                'metadata': {'name': 'cloudlab-composition-synthetic', 'generation': 2},
                'spec': {'validationActions': ['Deny'], 'failurePolicy': 'Fail'},
                'status': {'conditionStatus': {'ready': ready, 'conditions': [{'status': 'True', 'observedGeneration': generation}]}}}
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                files = {'policy.yaml': policy, 'resource.yaml': resource,
                    'context.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Context', 'metadata': {'name': 'composition'},
                        'spec': {'resources': [{'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'ready-policy'},
                            'data': {'policy.json': json.dumps(context)}}]}},
                    'kyverno-test.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Test', 'metadata': {'name': 'namespace'},
                        'policies': ['policy.yaml'], 'resources': ['resource.yaml'], 'context': 'context.yaml',
                        'results': [{'isValidatingPolicy': True, 'kind': 'Namespace', 'policy': policy['metadata']['name'],
                            'resources': [resource['metadata']['name']], 'result': 'pass' if ready and generation == 2 else 'fail'}]}}
                for name, value in files.items(): (directory / name).write_text(yaml.safe_dump(value))
                result = subprocess.run(['kyverno', 'test', str(directory)], capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr)[-10000:])
