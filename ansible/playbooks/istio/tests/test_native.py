"""Gateway native sources preserve authorization and reject foreign ownership."""
import copy
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import inputs
import initial_bootstrap
import kube
import native
import ownership
from playbooks.istio.tests.fixtures import accepted, documents, prepared


class NativeGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.contract, *_ = prepared()

    def observe(self, contract, state, payload, objects, *, stage='native'):
        with self.cluster(objects):
            return native.guard(contract, state, payload, stage=stage)

    def cluster(self, objects):
        stack = ExitStack()
        def get(kind, name=None, namespace=None): return objects.get((kind, name, namespace))
        for module in (native, ownership, kube, initial_bootstrap): stack.enter_context(patch.object(module, 'get', side_effect=get))
        credentials = [o for (kind, _, _), o in objects.items() if kind == 'secret' and o.get('metadata', {}).get('labels', {}).get('argocd.argoproj.io/secret-type') == 'repository']
        stack.enter_context(patch.object(native, 'kube', return_value=json.dumps({'items': credentials})))
        stack.enter_context(patch.object(ownership, 'wait', side_effect=lambda predicate, *a, **kw: predicate()))
        return stack

    def test_current_authorization_precedes_historical_overlay_and_sources_remain_distinct(self):
        contract, client, *_ = prepared()
        paths = [c.args[1] for c in client.request.call_args_list]
        self.assertLess(paths.index('repos/example/private/contents/identity/configmap.yaml?ref=' + 'c' * 40),
                        paths.index('repos/example/private/contents/identity/argo-values.yaml?ref=' + 'b' * 40))
        hosts = [o['spec']['hostnames'][0] for o in contract['resources'] if o['kind'] == 'HTTPRoute']
        self.assertIn('cd.example.invalid', hosts); self.assertNotIn('future.example.invalid', hosts)
        self.assertEqual([s['targetRevision'] for s in contract['application']['spec']['sources']],
                         [contract['configuration_revision'], 'main', 'b' * 40])

    def test_current_revocations_and_invalid_historical_or_shared_documents_fail_closed(self):
        for change in ('revoked', 'current-client', 'old-overlay', 'production', 'missing'):
            docs = documents()
            if change == 'revoked': docs['c' * 40, 'identity/configmap.yaml']['data']['revocations'] = json.dumps({'realms': {'platform': {'clients': ['argocd']}}})
            if change == 'current-client': docs['c' * 40, 'identity/configmap.yaml']['data']['desired_state'] = '{"realms":{"platform":{"clients":[]}}}'
            if change == 'old-overlay': docs['b' * 40, 'identity/argo-values.yaml']['argo-cd']['configs']['cm']['url'] = 'https://foreign.invalid'
            if change == 'production': docs['c' * 40, 'platform/certificates.yaml']['production'] = False
            if change == 'missing': del docs['b' * 40, 'identity/argo-values.yaml']
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, '^Authenticated gateway inputs are unavailable or invalid$'): prepared(docs)

    def test_file_size_api_and_revision_failures_remain_sanitized(self):
        _, _, public, values, binding = prepared()
        for bad in ({'type': 'dir'}, {'type': 'file', 'encoding': 'base64', 'size': 65537},
                    {'type': 'file', 'encoding': 'base64', 'size': 3, 'content': 'e30='}):
            class Client:
                def request(self, *a, **k): return bad
            with patch('playbooks.argocd.files.github_app.configuration_revision', side_effect=lambda v, read: read(Client(), 'c' * 40)), self.assertRaises(ValueError):
                inputs.prepare(values, public, binding, 'd' * 40)
        with patch('playbooks.argocd.files.github_app.configuration_revision', side_effect=RuntimeError('private detail')), self.assertRaisesRegex(ValueError, '^Authenticated gateway inputs are unavailable or invalid$'):
            inputs.prepare(values, public, binding, 'd' * 40)

    def test_native_and_legacy_readonly_guards_preserve_inventory(self):
        for stage in ('legacy', 'native'):
            payload, state, objects = accepted(self.contract, stage)
            self.assertEqual(self.observe(self.contract, state, payload, objects, stage=stage)['native_owner_verified'], stage == 'native')

    def test_app_project_reader_and_retained_identity_conflicts_refuse(self):
        for change in ('uid', 'source', 'stale', 'operation', 'running', 'skip', 'ignore', 'project', 'eso', 'eso-retention', 'secret-owner', 'extra-auth', 'duplicate', 'ca', 'tls', 'gateway', 'component'):
            payload, state, objects = accepted(self.contract)
            app = objects['application.argoproj.io', native.APP, 'argocd']
            if change == 'uid': app['metadata']['uid'] = 'replacement'
            if change == 'source': app['spec']['sources'][2]['targetRevision'] = 'e' * 40
            if change == 'stale': app['status']['sync']['revisions'][1] = 'e' * 40
            if change == 'operation': app['operation'] = {}
            if change == 'running': app['status']['operationState'] = {'phase': 'Running'}
            if change == 'skip': app['metadata']['annotations']['argocd.argoproj.io/skip-reconcile'] = 'true'
            if change == 'ignore': app['spec']['ignoreDifferences'] = [{'jsonPointers': ['/spec']}]
            if change == 'project': objects['appproject.argoproj.io', native.APP, 'argocd']['spec']['roles'] = [{'name': 'foreign'}]
            if change == 'eso': objects['externalsecret.external-secrets.io', native.APP + '-source', 'argocd']['spec']['target']['deletionPolicy'] = 'Delete'
            if change == 'eso-retention': objects['externalsecret.external-secrets.io', native.APP + '-source', 'argocd']['metadata']['annotations'].pop('argocd.argoproj.io/sync-options')
            if change == 'secret-owner': objects['secret', native.APP + '-source', 'argocd']['metadata']['ownerReferences'][0]['uid'] = 'foreign'
            if change == 'extra-auth': objects['secret', native.APP + '-source', 'argocd']['data']['password'] = 'eA=='
            if change == 'duplicate': objects['secret', 'duplicate', 'argocd'] = copy.deepcopy(objects['secret', native.APP + '-source', 'argocd'])
            if change == 'ca': objects['secret', 'istio-ca-secret', 'istio-system']['data']['ca-key.pem'] = 'foreign'
            if change == 'tls': objects['secret', 'cloudlab-gateway-tls', 'cloudlab-gateway-public']['metadata']['annotations'] = {}
            if change == 'gateway': objects['deployment', 'cloudlab-istio', 'cloudlab-gateway-public']['metadata']['uid'] = 'foreign'
            if change == 'component': objects['ServiceAccount', 'controller', 'istio-system']['metadata']['uid'] = 'foreign'
            with self.subTest(change=change), self.assertRaises(RuntimeError): self.observe(self.contract, state, payload, objects)

    def test_legacy_reader_collisions_are_not_adopted(self):
        for kind in ('secret', 'externalsecret.external-secrets.io', 'duplicate'):
            payload, state, objects = accepted(self.contract, 'legacy')
            _, _, native_objects = accepted(self.contract)
            source = 'secret' if kind == 'duplicate' else kind
            name = 'other-reader' if kind == 'duplicate' else native.APP + '-source'
            objects[source, name, 'argocd'] = native_objects[source, native.APP + '-source', 'argocd']
            with self.subTest(kind=kind), self.assertRaises(RuntimeError): self.observe(self.contract, state, payload, objects, stage='legacy')

    def test_route_defaults_are_normalized_but_behavior_and_stale_readiness_refuse(self):
        payload, state, objects = accepted(self.contract)
        route = objects['httproute.gateway.networking.k8s.io', 'argocd', 'cloudlab-gateway-public']
        route['spec']['parentRefs'][0].update(group='gateway.networking.k8s.io', kind='Gateway')
        rule = route['spec']['rules'][0]
        rule['matches'] = [{'path': {'type': 'PathPrefix', 'value': '/'}}]
        rule['backendRefs'][0].update(group='', kind='Service', weight=1)
        self.observe(self.contract, state, payload, objects)
        rule['backendRefs'][0]['weight'] = 2
        with self.assertRaises(RuntimeError): self.observe(self.contract, state, payload, objects)
        rule['backendRefs'][0]['weight'] = 1
        route['status']['parents'][0]['conditions'][0]['observedGeneration'] = 0
        with self.assertRaises(RuntimeError): self.observe(self.contract, state, payload, objects)

    def test_accepted_native_seed_observes_before_snapshot_or_zone_and_never_writes(self):
        payload, state, objects = accepted(self.contract)
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'ownership.json').write_text(json.dumps(state))
            with patch.object(initial_bootstrap, 'BASE', Path(directory)), self.cluster(objects), \
                    patch.object(initial_bootstrap, 'selected_zone', side_effect=AssertionError('snapshot zone read')), \
                    patch.object(initial_bootstrap, 'application', side_effect=AssertionError('snapshot construction')), \
                    patch.object(initial_bootstrap, 'record') as record, patch.object(initial_bootstrap, 'kube') as write:
                # guard imports application only for the legacy branch and must never call it here.
                self.assertFalse(initial_bootstrap.run(payload | {'native': self.contract})['changed'])
                record.assert_not_called(); write.assert_not_called()

    def test_accepted_prebinding_observes_legacy_and_no_receipt_refuses_existing_objects(self):
        payload, state, objects = accepted(self.contract, 'legacy')
        overlay = documents()['b' * 40, 'identity/argo-values.yaml']
        objects['configmap', 'argocd-cm', 'argocd'] = {'metadata': {'annotations': {
            'argocd.argoproj.io/tracking-id': 'cloudlab-argocd:/ConfigMap:argocd/argocd-cm'}},
            'data': overlay['argo-cd']['configs']['cm']}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ownership.json'; path.write_text(json.dumps(state))
            with patch.object(initial_bootstrap, 'BASE', Path(directory)), self.cluster(objects), \
                    patch.object(initial_bootstrap, 'record') as record, patch.object(initial_bootstrap, 'kube') as write:
                self.assertFalse(initial_bootstrap.run(payload)['changed'])
                record.assert_not_called(); write.assert_not_called()
                path.unlink()
                with self.assertRaisesRegex(RuntimeError, 'without its ownership checkpoint'): initial_bootstrap.run(payload)
                write.assert_not_called()

    def test_absent_binding_after_native_handoff_cannot_defer_retirement(self):
        payload, state, objects = accepted(self.contract)
        with self.cluster(objects), self.assertRaisesRegex(RuntimeError, 'initial gateway seed changed'):
            native.observe_legacy(payload, state)
        import yaml
        play = yaml.safe_load((Path(__file__).resolve().parents[4] / 'ansible/playbooks/istio/020-retire-runtime.yml').read_text())[0]
        attestation = next(task for task in play['tasks'] if 'ansible.builtin.command' in task)
        self.assertNotIn('when', attestation)

    def test_route_readiness_requires_its_declared_gateway_namespace_and_listener(self):
        payload, state, objects = accepted(self.contract)
        route = objects['httproute.gateway.networking.k8s.io', 'argocd', 'cloudlab-gateway-public']
        parent = route['status']['parents'][0]
        for ref in ({'name': 'cloudlab', 'sectionName': 'https'},
                    {'group': 'gateway.networking.k8s.io', 'kind': 'Gateway', 'name': 'cloudlab', 'sectionName': 'https'},
                    {'group': 'gateway.networking.k8s.io', 'kind': 'Gateway', 'name': 'cloudlab',
                     'namespace': 'cloudlab-gateway-public', 'sectionName': 'https'}):
            parent['parentRef'] = ref
            self.observe(self.contract, state, payload, objects)
        expected = copy.deepcopy(parent['parentRef'])
        for key, value in (('name', 'foreign-gateway'), ('namespace', 'foreign-namespace'),
                           ('sectionName', 'http'), ('group', 'foreign.io'), ('kind', 'Service'), ('port', 443)):
            parent['parentRef'] = expected | {key: value}
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'route current generation'):
                self.observe(self.contract, state, payload, objects)
        parent.pop('parentRef')
        with self.assertRaisesRegex(RuntimeError, 'route current generation'):
            self.observe(self.contract, state, payload, objects)

    def test_unchanged_service_uid_cannot_authorize_external_gateway_exposure(self):
        for stage in ('legacy', 'native'):
            for change in ('LoadBalancer', 'NodePort', 'externalIPs', 'nodePort'):
                payload, state, objects = accepted(self.contract, stage)
                service = objects['service', 'cloudlab-istio', 'cloudlab-gateway-public']
                if change in ('LoadBalancer', 'NodePort'): service['spec']['type'] = change
                if change == 'externalIPs': service['spec']['externalIPs'] = ['192.0.2.1']
                if change == 'nodePort': service['spec']['ports'][0]['nodePort'] = 30443
                with self.subTest(stage=stage, change=change), self.assertRaisesRegex(RuntimeError, 'service has external exposure'):
                    self.observe(self.contract, state, payload, objects, stage=stage)
                with self.cluster(objects), self.assertRaisesRegex(RuntimeError, 'service has external exposure'):
                    native.observe_legacy(payload, state)
