import copy
import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from playbooks.keycloak.files.integrations import argo as contract_for

runtime = importlib.import_module('playbooks.keycloak.files.argo')


class ArgoRecoveryTests(unittest.TestCase):
    def test_native_pending_recovery_authenticates_equal_profiles_before_binding(self):
        import base64
        import hashlib
        from contextlib import ExitStack
        from unittest.mock import Mock
        import yaml
        from playbooks.keycloak.files import ownership
        from playbooks.argocd.files import source_transition
        from playbooks.data.files import native
        repo = ownership.PUBLIC_REPOSITORY.rsplit('/', 1)[0] + '/private.git'
        old = {'valuesRepository': repo, 'valuesRevision': 'a' * 40}
        new = dict(old, valuesRevision='b' * 40)
        public = yaml.safe_load((Path(__file__).resolve().parents[4] / 'gitops/roots/public/values.yaml').read_text())
        public['identity']['application']['enabled'] = True
        chart = Path(__file__).resolve().parents[4] / 'gitops/roots/public'
        files = {str(path.relative_to(chart)).replace('\\', '/'): path.read_bytes() for path in chart.rglob('*') if path.is_file()}
        values = copy.deepcopy(public); values['identity']['argo'] = old
        rendered = native.render_objects(files, [values])
        declarations = {obj['kind']: obj for obj in rendered if obj.get('metadata', {}).get('name') == ownership.APP}
        document = {'installationRevision': ownership.INSTALLATION_REVISION, 'loginHost': 'login.example.invalid',
            'adminHost': 'identity-admin.internal.example.invalid', 'database': 'keycloak', 'databaseRole': 'keycloak',
            'databaseHost': 'cloudlab-postgres-rw.cloudlab-data.svc.cluster.local', 'databasePort': 5432,
            'databaseCA': 'fixture-ca', 'trustedProxyAddresses': ['10.42.0.0/24'],
            'retiredEmergencyItem': 'keycloak-emergency-' + 'a' * 32}
        app = {'metadata': {'uid': 'app', 'labels': {'cloudlab.io/owner': runtime.OWNER}, 'ownerReferences': [
            {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': ownership.APP,
             'uid': 'parent', 'controller': True, 'blockOwnerDeletion': True}]},
            'spec': ownership.installation_values(document, telemetry=public['observability']['enabled'])}
        original = {'repoURL': ownership.PUBLIC_REPOSITORY, 'targetRevision': 'main', 'path': 'gitops/roots/public',
            'helm': {'releaseName': 'cloudlab-public-root', 'valuesObject': {'identity': {'enabled': True, 'argo': old}}}}
        patched = copy.deepcopy(original); patched['helm']['valuesObject']['identity']['argo'] = new
        root = {'metadata': {'uid': 'root'}, 'spec': {'project': 'cloudlab-root', 'source': patched,
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
            'ignoreDifferences': native.delegations(), 'syncPolicy': {'automated': {'prune': False},
            'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true', 'RespectIgnoreDifferences=true']}}}
        project = copy.deepcopy(declarations['AppProject'])
        project['metadata'].update(uid='project', annotations={'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/AppProject:argocd/' + ownership.APP})
        parent = copy.deepcopy(declarations['ApplicationSet'])
        parent['metadata'].update(uid='parent', annotations={'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/ApplicationSet:argocd/' + ownership.APP})
        parent['status'] = {'conditions': [{'type': 'ParametersGenerated', 'status': 'True'}]}
        root_project = {'metadata': {'uid': 'root-project'}, 'spec': {'sourceRepos': [ownership.PUBLIC_REPOSITORY],
            'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}],
            'clusterResourceWhitelist': [{'group': '', 'kind': 'Namespace'}], 'namespaceResourceWhitelist': [
                {'group': 'argoproj.io', 'kind': name} for name in ('Application', 'AppProject', 'ApplicationSet')] +
                [{'group': 'external-secrets.io', 'kind': 'ExternalSecret'}]}}
        objects = {('application.argoproj.io', ownership.APP): app, ('application.argoproj.io', 'cloudlab-public-root'): root,
            ('applicationset.argoproj.io', ownership.APP): parent, ('appproject.argoproj.io', ownership.APP): project,
            ('appproject.argoproj.io', 'cloudlab-root'): root_project,
            ('statefulset', 'argocd-application-controller'): {'metadata': {'uid': 'controller'}, 'spec': {'replicas': 0}},
            ('keycloak.k8s.keycloak.org', 'cloudlab-keycloak'): {'metadata': {'uid': 'server'}},
            ('externalsecret.external-secrets.io', 'cloudlab-identity-installation-source'): {'metadata': {'uid': 'reader'}},
            ('secret', 'cloudlab-identity-installation-source'): {'metadata': {'uid': 'secret'}}}
        contract = contract_for('https://login.example.invalid/realms/platform', 'https://console.example.invalid', ['https://cd.internal.example.invalid'])
        payload = {'revision': 'c' * 40, 'values': {'loginHost': document['loginHost']}, 'argo': {'target': new,
            'configuration': contract['helm'], 'client': contract['client'], 'recovery': True,
            'currentSecurityProjection': {'revision': 'd' * 40, 'configuration': contract['helm'], 'client': contract['client']}}}
        checkpoint = {'phase': 'paused', 'target': new, 'publicRevision': 'c' * 40, 'originalSource': original,
            'patchedSource': patched, 'root_uid': 'root', 'controller_uid': 'controller', 'project_uid': 'root-project'}
        for change in ('equal', 'profile', 'context', 'ordinary', 'revocation', 'active'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                base = Path(directory); events = []; requests = []
                if change == 'active':
                    active = ownership.SUPPORTED_INSTALLATION_REVISIONS[1]
                    public['identity']['application']['installationRevision'] = active
                    app['spec']['source']['targetRevision'] = active
                    parent['spec']['template']['spec']['source']['targetRevision'] = active
                state = {'phase': 'scoped', 'uid': 'app', 'revision': ownership.INSTALLATION_REVISION, 'native': {
                    'phase': 'accepted', 'root_uid': 'root', 'project_uid': 'project', 'application_uid': 'app',
                    'keycloak_uid': 'server', 'values': app['spec']['source']['helm']['valuesObject'], 'original_revision': 'main',
                    'parent_uid': 'parent', 'reader_uid': 'reader', 'secret_uid': 'secret'}}
                for name, body in (('ownership.json', state), ('retirement.json', {'phase': 'accepted', 'application_uid': 'app', 'keycloak_uid': 'server'}),
                        ('identity-values-binding.json', checkpoint)):
                    (base / name).write_text(json.dumps(body))
                current_payload = copy.deepcopy(payload)
                if change == 'ordinary': current_payload['argo'].pop('recovery')
                supplied = copy.deepcopy(checkpoint)
                if change == 'context': supplied['controller_uid'] = 'foreign'
                api = Mock(); client = Mock()
                api.request.side_effect = lambda method, path, body=None: {'token': 'synthetic-token'} if method == 'POST' else {}
                def request(method, path, body=None):
                    requests.append((method, path))
                    if method == 'DELETE':
                        events.append('revoke')
                        if change == 'revocation': raise RuntimeError('Synthetic revocation failure')
                        return None
                    if '/contents/' not in path:
                        return {'full_name': native.repository(repo), 'private': True, 'default_branch': 'main'}
                    revision = path.split('?ref=')[1]
                    content = copy.deepcopy(document)
                    if change == 'profile' and revision == new['valuesRevision']: content['databaseCA'] = 'changed-ca'
                    raw = yaml.safe_dump(content).encode()
                    return {'type': 'file', 'encoding': 'base64', 'path': 'identity/keycloak-values.yaml', 'size': len(raw),
                        'content': base64.b64encode(raw).decode(), 'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
                client.request.side_effect = request
                def read(kind, name, *args): return copy.deepcopy(objects.get((kind, name)))
                for module in (runtime, ownership, source_transition):
                    stack.enter_context(patch.object(module, 'get', side_effect=read))
                stack.enter_context(patch.object(runtime, 'BASE', base))
                stack.enter_context(patch.object(native, 'BINDING', base / 'identity-values-binding.json'))
                stack.enter_context(patch.object(source_transition, 'BASE', base))
                stack.enter_context(patch.object(native, 'receipt', side_effect=lambda path: json.loads(path.read_text())))
                stack.enter_context(patch.object(source_transition, 'pending_identity_checkpoint', return_value=checkpoint))
                stack.enter_context(patch.object(runtime, 'pending_identity_checkpoint', return_value=supplied))
                stack.enter_context(patch.object(runtime, 'pending_identity_target', return_value=new['valuesRevision']))
                stack.enter_context(patch.object(runtime, 'prerequisites'))
                stack.enter_context(patch.object(runtime, 'private_inputs', return_value=({'realms': {'platform': {'clients': [contract['client']]}}}, {'realms': {}}, new['valuesRevision'])))
                stack.enter_context(patch.object(runtime, 'application_ready', return_value=True))
                stack.enter_context(patch.object(native, 'published_source', return_value=(public, 'c' * 40)))
                stack.enter_context(patch.object(native.source_snapshot, 'chart_files', return_value=files))
                stack.enter_context(patch.object(native, 'kube', return_value='{"items":[]}'))
                stack.enter_context(patch.object(native, 'source_credentials', return_value={'APP_ID': '1', 'INSTALLATION_ID': '2', 'PRIVATE_KEY': 'synthetic'}))
                stack.enter_context(patch.object(native, 'app_token', return_value='synthetic-app-token'))
                stack.enter_context(patch.object(native, 'verify_installation'))
                stack.enter_context(patch.object(native, 'GitHub', side_effect=[api, client]))
                check = stack.enter_context(patch.object(runtime, 'check', side_effect=lambda *args: events.append('protocol')))
                stack.enter_context(patch.object(runtime, 'proxy_privacy'))
                stack.enter_context(patch.object(runtime, 'public_address'))
                stack.enter_context(patch.object(runtime, 'private_request', return_value={'error': 'invalid_grant'}))
                bind = stack.enter_context(patch.object(runtime, 'bind_identity', side_effect=lambda *args: events.append('bind') or {'changed': False}))
                if change in ('equal', 'active'):
                    runtime.run(current_payload)
                    self.assertLess(events.index('revoke'), events.index('protocol'))
                    self.assertEqual(events[-1], 'bind')
                    self.assertEqual([path for method, path in requests if '/contents/' in path], [
                        'repos/' + native.repository(repo) + '/contents/identity/keycloak-values.yaml?ref=' + target['valuesRevision'] for target in (old, new)])
                else:
                    with self.assertRaises(RuntimeError): runtime.run(current_payload)
                    bind.assert_not_called(); check.assert_not_called()
                    if change in ('profile', 'revocation'): self.assertEqual(events, ['revoke'])
                    else: self.assertEqual(requests, [])

    def test_current_projection_and_pending_target_are_required_before_binding(self):
        contract = contract_for('https://login.example.invalid/realms/platform', 'https://console.example.invalid',
                                ['https://cd.internal.example.invalid'])
        original = {'revision': 'c' * 40, 'values': {'loginHost': 'login.example.invalid'}, 'argo': {
            'target': {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'a' * 40},
            'configuration': contract['helm'], 'client': contract['client'], 'recovery': True,
            'currentSecurityProjection': {'revision': 'b' * 40, 'configuration': copy.deepcopy(contract['helm']), 'client': copy.deepcopy(contract['client'])}}}
        source = {'realms': {'platform': {'clients': [contract['client']]}}}
        for change in ('valid', 'missing', 'mutable', 'changed', 'pending'):
            payload = copy.deepcopy(original)
            if change == 'missing': payload['argo'].pop('currentSecurityProjection')
            if change == 'mutable': payload['argo']['currentSecurityProjection']['revision'] = 'main'
            if change == 'changed': payload['argo']['currentSecurityProjection']['client']['callbacks'] = ['https://foreign.invalid']
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                (base / 'ownership.json').write_text(json.dumps({'phase': 'scoped', 'uid': 'owned'}))
                current = {'metadata': {'uid': 'owned', 'labels': {'cloudlab.io/owner': runtime.OWNER}}, 'spec': {'source': {'repoURL': 'public'}}}
                with patch.object(runtime, 'BASE', base), patch.object(runtime, 'prerequisites'), \
                        patch.object(runtime, 'get', return_value=current), patch.object(runtime, 'application_ready', return_value=True), \
                        patch.object(runtime, 'private_inputs', return_value=(source, {'realms': {}}, 'a' * 40)), \
                        patch.object(runtime, 'pending_identity_target', return_value='a' * 40) as pending, \
                        patch.object(runtime, 'pending_identity_checkpoint', return_value={'root_uid': 'owned', 'patchedSource': {'repoURL': 'public'}}), \
                        patch.object(runtime, 'check'), patch.object(runtime, 'proxy_privacy'), \
                        patch.object(runtime, 'public_address'), \
                        patch.object(runtime, 'private_request', return_value={'error': 'invalid_grant'}), \
                        patch.object(runtime, 'bind_identity', return_value={'changed': False}) as bind:
                    if change == 'pending': pending.side_effect = RuntimeError('No exact pending checkpoint')
                    if change == 'valid':
                        runtime.run(payload)
                        bind.assert_called_once_with(payload, payload['argo']['target'])
                    else:
                        with self.assertRaises(RuntimeError): runtime.run(payload)
                        bind.assert_not_called()
                        if change != 'pending': pending.assert_not_called()

    def test_identity_prerequisite_uses_data_observer_and_propagates_pending_recovery(self):
        from playbooks.keycloak.files import ownership
        from playbooks.data.files import native as data_native
        payload = {'revision': 'a' * 40, 'values': {'database': 'keycloak', 'databaseRole': 'keycloak'}}
        record = unittest.mock.Mock()
        record.read_text.side_effect = [json.dumps({'retention_complete': True, 'restore': {'physical_restore': True}}),
                                       json.dumps({'verified_at': 1, 'external_binding': True})] * 2
        for recovery in (None, {'checkpoint': {'dataActivation': {'immutable': 'synthetic'}}, 'sourceState': 'patched'}):
            with self.subTest(recovery=recovery is not None), patch.object(ownership, 'Path', return_value=record), \
                    patch.object(ownership, 'application_ready', return_value=True) as ready, \
                    patch('playbooks.access.files.native.prerequisite'), \
                    patch.object(data_native, 'prerequisite', return_value={'identity': {'enabled': True, 'database': 'keycloak', 'role': 'keycloak'}}) as data, \
                    patch.object(ownership, 'get', return_value={'metadata': {'generation': 1},
                        'status': {'applied': True, 'observedGeneration': 1}}) as read:
                ownership.prerequisites(payload, access_recovery=recovery)
                data.assert_called_once_with(payload, recovery=recovery)
                self.assertEqual([call.args[0] for call in ready.call_args_list], ['cloudlab-keycloak-operator', 'cloudlab-argocd'])
                read.assert_called_once_with('database.postgresql.cnpg.io', 'keycloak', 'cloudlab-data')
