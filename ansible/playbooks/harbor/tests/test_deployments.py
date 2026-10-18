import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from playbooks.harbor.files import artifacts, deployments
from playbooks.harbor.tests.fixtures import deployment_artifacts


class DeploymentTests(unittest.TestCase):
    def test_repeat_verification_rejects_widened_quotas_or_network_access(self):
        quota = {'spec': {'hard': dict(deployments.QUOTA)}}
        policy = {'spec': {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress']}}
        with patch.object(deployments, 'get', side_effect=lambda kind, *args: quota if kind == 'resourcequota' else policy):
            deployments.posture()
            quota['spec']['hard']['pods'] = '7'
            with self.assertRaisesRegex(RuntimeError, 'quota changed'): deployments.posture()
            quota['spec']['hard']['pods'] = '6'
            policy['spec']['egress'] = [{}]
            with self.assertRaisesRegex(RuntimeError, 'networking changed'): deployments.posture()

    def test_cleanup_uses_recorded_namespace_uid_and_preserves_interrupted_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'proof.json'
            record = {'nonce': 'a' * 32, 'uid': 'namespace-original', 'phase': 'ready'}
            path.write_text(json.dumps(record))
            namespace = {'metadata': {'uid': record['uid'], 'labels': dict(deployments.NAMESPACE_LABELS,
                                               **{'cloudlab.io/proof-owner': record['nonce']})}}
            def get(kind, name=None, namespace=None):
                return {'items': [{}, {}, {}, {}]} if kind == 'pods' else namespace_object
            namespace_object = namespace
            with patch.object(deployments, 'RECORD', path), patch.object(deployments, 'get', side_effect=get), \
                    patch.object(deployments, 'verify', return_value={'active': True}), \
                    patch.object(deployments, 'kube', side_effect=RuntimeError('synthetic interrupted delete')) as kube, \
                    patch.object(deployments, 'wait'):
                with self.assertRaisesRegex(RuntimeError, 'interrupted delete'): deployments.cleanup()
                retained = json.loads(path.read_text())
                self.assertEqual(retained, dict(record, phase='cleaning'))
                self.assertEqual(kube.call_args.kwargs['document']['preconditions'], {'uid': record['uid']})
                namespace_object = copy.deepcopy(namespace)
                namespace_object['metadata']['uid'] = 'foreign-replacement'
                kube.reset_mock()
                with self.assertRaisesRegex(RuntimeError, 'ownership changed'): deployments.cleanup()
                kube.assert_not_called()
                self.assertEqual(json.loads(path.read_text()), retained)
                namespace_object = None
                self.assertFalse(deployments.cleanup()['registry_artifacts_removed'])
                self.assertFalse(path.exists())

    def test_interrupted_first_rollout_preserves_nonce_uid_and_exact_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'proof.json'
            state, applied = {}, []
            def get(kind, name=None, namespace=None):
                if kind == 'namespace': return state.get('namespace')
                if kind == 'deployment': return state.get(name)
                if kind == 'externalsecret':
                    return {'metadata': {}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
                raise AssertionError(kind)
            def create(*args, document=None, **kwargs):
                self.assertEqual(args[0], 'create')
                state['namespace'] = copy.deepcopy(document)
                state['namespace']['metadata']['uid'] = 'namespace-original'
            def apply(document):
                if document['kind'] == 'Deployment':
                    name = document['metadata']['name']
                    state[name] = copy.deepcopy(document)
                    state[name]['metadata']['uid'] = name + '-original'
                    applied.append(copy.deepcopy(document))
            with patch.object(deployments, 'RECORD', path), patch.object(deployments, 'get', side_effect=get), \
                    patch.object(deployments, 'host', return_value='harbor.example.invalid'), \
                    patch.object(deployments, 'kube', side_effect=create) as kube, \
                    patch.object(deployments, 'apply', side_effect=apply), \
                    patch.object(deployments, 'wait', side_effect=lambda predicate, *args, **kwargs: predicate()), \
                    patch.object(deployments, 'ready', side_effect=RuntimeError('synthetic interrupted wait')):
                document = deployment_artifacts()
                with self.assertRaisesRegex(RuntimeError, 'interrupted wait'): deployments.prepare(document)
                recorded = json.loads(path.read_text())
                self.assertEqual(recorded['deployments'], {'cloudlab-public': 'cloudlab-public-original'})
                self.assertEqual(recorded['steps']['cloudlab-public'], 0)
                # Simulate process death between native create and UID delivery.
                recorded['deployments'] = {}
                path.write_text(json.dumps(recorded))
                with self.assertRaisesRegex(RuntimeError, 'interrupted wait'): deployments.prepare(document)
                repeated = json.loads(path.read_text())
                self.assertEqual(repeated['nonce'], recorded['nonce'])
                self.assertEqual(repeated['artifacts'], document)
                self.assertEqual(repeated['deployments'], {'cloudlab-public': 'cloudlab-public-original'})
                self.assertEqual(applied[0], applied[1])
                kube.assert_called_once()
                state['cloudlab-public']['metadata']['uid'] = 'foreign-replacement'
                with self.assertRaisesRegex(RuntimeError, 'cannot be adopted'): deployments.prepare(document)
                self.assertEqual(len(applied), 2)
                changed = copy.deepcopy(document)
                changed['cloudlab-public'][0]['digest'] = 'sha256:' + 'f' * 64
                with self.assertRaisesRegex(RuntimeError, 'original deployed'): deployments.prepare(changed)
                self.assertEqual(json.loads(path.read_text()), repeated)

    def test_inputs_cannot_expand_projects_history_payload_or_export_credentials(self):
        document = deployment_artifacts()
        self.assertEqual(deployments.artifacts(document), document)
        for mutation in ('project', 'count', 'duplicate', 'payload', 'secret'):
            value = copy.deepcopy(document)
            rows = value['cloudlab-public']
            if mutation == 'project': value['foreign'] = rows
            if mutation == 'count': rows.pop()
            if mutation == 'duplicate': rows[1]['digest'] = rows[0]['digest']
            if mutation == 'payload': rows[0]['payload_bytes'] = 1
            if mutation == 'secret': rows[0]['password'] = 'synthetic-never-deliver'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): deployments.artifacts(value)

    def test_workloads_use_restricted_profile_bounded_rollout_and_only_their_pull_robot(self):
        for project, rows in deployment_artifacts().items():
            deployment = deployments.deployment(project, rows[0], 'harbor.example.invalid')
            spec = deployment['spec']
            pod = spec['template']['spec']
            container = pod['containers'][0]
            self.assertEqual(spec['revisionHistoryLimit'], 5)
            self.assertEqual(spec['strategy']['rollingUpdate'], {'maxSurge': 0, 'maxUnavailable': 1})
            self.assertFalse(pod['automountServiceAccountToken'])
            self.assertEqual(pod['imagePullSecrets'], [{'name': project + '-pull'}])
            self.assertTrue(pod['securityContext']['runAsNonRoot'])
            self.assertEqual(pod['securityContext']['seccompProfile']['type'], 'RuntimeDefault')
            self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
            self.assertFalse(container['securityContext']['allowPrivilegeEscalation'])
            self.assertEqual(container['securityContext']['capabilities'], {'drop': ['ALL']})
            self.assertEqual(container['imagePullPolicy'], 'Always')
            self.assertTrue(container['image'].endswith('@' + rows[0]['digest']))
            self.assertEqual(container['resources']['limits'], {'cpu': '100m', 'memory': '64Mi'})
            self.assertEqual(container['readinessProbe']['timeoutSeconds'], 5)
            self.assertNotIn('hostPath', json.dumps(pod))
            delivery = deployments.delivery(project, 'harbor.example.invalid')['spec']
            self.assertEqual(delivery['dataFrom'], [{'extract': {'key': 'harbor-' + project + '-pull'}}])
            self.assertEqual(delivery['target']['template']['type'], 'kubernetes.io/dockerconfigjson')
            self.assertNotIn('push', json.dumps(delivery))

    def test_pod_readiness_requires_new_uid_both_nodes_and_actual_digest(self):
        row = deployment_artifacts()['cloudlab-public'][0]
        reference = 'harbor.example.invalid/cloudlab-public/bootstrap@' + row['digest']
        pods = [{'metadata': {'name': 'pod-' + str(number), 'uid': 'pod-' + str(number),
                             'labels': {'cloudlab.io/project': 'cloudlab-public'}},
                 'spec': {'nodeName': 'node-' + str(number), 'containers': [{'image': reference}]},
                 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}],
                            'containerStatuses': [{'imageID': reference}]}} for number in (1, 2)]
        def check():
            return deployments.ready_pods('cloudlab-public', row, 'harbor.example.invalid', {'node-1', 'node-2'})
        with patch.object(deployments, 'get', return_value={'items': pods}):
            self.assertTrue(check())
            self.assertFalse(deployments.ready_pods('cloudlab-public', row, 'harbor.example.invalid',
                                                   {'node-1', 'node-2'}, removed='pod-1'))
            for mutation in ('node', 'image', 'ready'):
                changed = copy.deepcopy(pods)
                if mutation == 'node': changed[1]['spec']['nodeName'] = 'node-1'
                if mutation == 'image': changed[0]['status']['containerStatuses'][0]['imageID'] = 'sha256:' + 'f' * 64
                if mutation == 'ready': changed[0]['status']['conditions'][0]['status'] = 'False'
                with patch.object(deployments, 'get', return_value={'items': changed}): self.assertFalse(check())

    def test_native_history_rejects_replaced_namespace_missing_revision_or_modified_retained_template(self):
        document = deployment_artifacts()
        record = {'nonce': 'a' * 32, 'uid': 'namespace-original', 'artifacts': document,
                  'deployments': {project: project + '-original' for project in document}}
        namespace = {'metadata': {'uid': record['uid'], 'labels': dict(deployments.NAMESPACE_LABELS,
                                                **{'cloudlab.io/proof-owner': record['nonce']})}}
        replicas = []
        for project, rows in document.items():
            for number, row in enumerate(rows):
                template = deployments.deployment(project, row, 'harbor.example.invalid')['spec']['template']
                replicas.append({'metadata': {'uid': project + '-revision-' + str(number), 'ownerReferences': [{
                    'apiVersion': 'apps/v1', 'kind': 'Deployment', 'name': project,
                    'uid': record['deployments'][project], 'controller': True, 'blockOwnerDeletion': True}]},
                    'spec': {'template': template}})
        def get(kind, name=None, namespace=None):
            if kind == 'namespace': return copy.deepcopy(namespace_object)
            if kind == 'deployment': return {'metadata': {'uid': record['deployments'][name]}}
            if kind == 'replicaset': return {'items': current_replicas}
            raise AssertionError(kind)
        namespace_object, current_replicas = namespace, replicas
        with patch.object(deployments, 'get', side_effect=get), patch.object(deployments, 'host', return_value='harbor.example.invalid'):
            self.assertEqual(sum(map(len, deployments.history(record).values())), 12)
            namespace_object = copy.deepcopy(namespace)
            namespace_object['metadata']['uid'] = 'replaced'
            with self.assertRaises(RuntimeError): deployments.history(record)
            namespace_object = namespace
            current_replicas = replicas[:-1]
            with self.assertRaises(RuntimeError): deployments.history(record)
            current_replicas = copy.deepcopy(replicas)
            current_replicas[0]['spec']['template']['spec']['containers'][0]['securityContext']['allowPrivilegeEscalation'] = True
            with self.assertRaises(RuntimeError): deployments.history(record)

    def test_local_request_sends_only_public_receipt_fields_and_uses_existing_native_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = Mock(path=Path(temporary), values={'VM_HOST': 'synthetic-host'})
            client.plan.return_value = {'changes': 0}
            document = deployment_artifacts()
            record = {'recipe': 1, 'base': artifacts.PYTHON, 'verified_at': 1, 'projects': {
                project: dict(rows[0], rollback=dict(zip(artifacts.ROLLBACK_TAGS, rows[1:])))
                for project, rows in document.items()}}
            record['projects']['cloudlab-public']['private_extra'] = 'synthetic-never-deliver'
            record['projects']['cloudlab-public']['rollback'][artifacts.ROLLBACK_TAGS[0]]['private_extra'] = 'synthetic-never-deliver'
            directory = client.path / 'artifacts'
            directory.mkdir()
            (directory / 'receipt.json').write_text(json.dumps(record))
            with patch.object(artifacts, 'ssh', return_value='{"active":true,"rollback_replicasets":10}') as ssh:
                artifacts.deployment_proof(client, 'prepare')
                exported = json.loads(ssh.call_args.kwargs['input'])
                self.assertNotIn('synthetic-never-deliver', json.dumps(exported))
                self.assertEqual(exported, deployment_artifacts())
                self.assertEqual(ssh.call_args.args[2], 'python3 /opt/cloudlab/playbooks/harbor/files/deployments.py prepare')
                client.plan.assert_called_once_with(verify=True)
                client.plan.return_value = {'changes': 1}
                ssh.reset_mock()
                with self.assertRaises(ValueError): artifacts.deployment_proof(client, 'prepare')
                ssh.assert_not_called()
