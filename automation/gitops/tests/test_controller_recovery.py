import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import bootstrap


class ControllerRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.current = {'kind': 'StatefulSet', 'metadata': {
            'name': 'argocd-application-controller', 'namespace': 'argocd', 'uid': 'retained',
            'resourceVersion': '8', 'annotations': {'argocd.argoproj.io/tracking-id':
                'cloudlab-argocd:apps/StatefulSet:argocd/argocd-application-controller'}},
            'spec': {'replicas': 1, 'template': {'spec': {'containers': [{
                'name': 'application-controller', 'image': 'pinned-image',
                'env': [{'name': 'UNRELATED', 'value': 'preserved'}],
                'resources': {'requests': {'cpu': '250m', 'memory': '256Mi'},
                              'limits': {'memory': '1Gi'}}}]}}}}
        self.desired = copy.deepcopy(self.current)
        c = self.desired['spec']['template']['spec']['containers'][0]
        c['resources']['requests']['memory'] = '512Mi'
        c['resources']['limits']['memory'] = '2Gi'
        c['env'].append({'name': 'GOMEMLIMIT', 'value': '1600MiB'})
        self.state = {'phase': 'accepted', 'version': 'fixture', 'identities': {
            'statefulset.apps/argocd-application-controller': 'retained',
            'secret/argocd-secret': 'signing', 'secret/argocd-redis': 'redis'}}
        self.pod = {'metadata': {'name': 'argocd-application-controller-0', 'ownerReferences': [
            {'kind': 'StatefulSet', 'controller': True, 'uid': 'retained'}]}, 'status': {
            'conditions': [{'type': 'Ready', 'status': 'False'}], 'containerStatuses': [{
                'name': 'application-controller', 'lastState': {'terminated': {'reason': 'OOMKilled'}}}]}}

    def plan(self, state=None, current=None, pod=None, desired=None):
        return bootstrap.controller_memory_patch(state or self.state, current or self.current,
                                                 pod or self.pod, desired or self.desired)

    def test_oom_repair_tests_identity_and_changes_only_memory(self):
        before = copy.deepcopy(self.current)
        changes = self.plan()
        self.assertEqual(changes[:2], [
            {'op': 'test', 'path': '/metadata/uid', 'value': 'retained'},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '8'}])
        self.assertEqual({c['path'] for c in changes[2:]}, {
            '/spec/template/spec/containers/0/resources/requests/memory',
            '/spec/template/spec/containers/0/resources/limits/memory',
            '/spec/template/spec/containers/0/env/-'})
        self.assertEqual(self.current, before)
        self.assertEqual(self.plan(current=self.desired), [])

    def test_unaccepted_replaced_foreign_or_ready_workload_is_refused(self):
        for kind in ('checkpoint', 'uid', 'tracking', 'owner', 'ready', 'cause', 'image', 'replicas', 'ambiguous'):
            state, current, pod, desired = map(copy.deepcopy, (self.state, self.current, self.pod, self.desired))
            if kind == 'checkpoint': state['phase'] = 'seeded'
            if kind == 'uid': current['metadata']['uid'] = 'replacement'
            if kind == 'tracking': current['metadata']['annotations'] = {}
            if kind == 'owner': pod['metadata']['ownerReferences'][0]['uid'] = 'other'
            if kind == 'ready': pod['status']['conditions'][0]['status'] = 'True'
            if kind == 'cause': pod['status']['containerStatuses'][0]['lastState'] = {}
            if kind == 'image': desired['spec']['template']['spec']['containers'][0]['image'] = 'upgrade'
            if kind == 'replicas': current['spec']['replicas'] = 0
            if kind == 'ambiguous': current['spec']['template']['spec']['containers'][0]['env'] = [
                {'name': 'GOMEMLIMIT', 'value': 'old'}, {'name': 'GOMEMLIMIT', 'value': 'other'}]
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                self.plan(state, current, pod, desired)

    def test_unreviewed_memory_bounds_are_refused(self):
        for kind in ('request', 'limit', 'runtime'):
            desired = copy.deepcopy(self.desired)
            c = desired['spec']['template']['spec']['containers'][0]
            if kind == 'request': c['resources']['requests']['memory'] = '16Gi'
            if kind == 'limit': c['resources']['limits']['memory'] = '64Gi'
            if kind == 'runtime': c['env'][-1]['value'] = '3GiB'
            with self.subTest(kind=kind), self.assertRaises(RuntimeError): self.plan(desired=desired)

    def test_native_recovery_requires_credentials_and_hands_back_to_argo(self):
        app = {'spec': {'project': 'cloudlab-platform', 'sources': [{
            'repoURL': 'public', 'path': 'platform/delivery/argocd', 'targetRevision': 'main'},
            {'repoURL': 'retained-private', 'targetRevision': 'retained-pin'}]}}
        objects = {'statefulset': self.current, 'pod': self.pod, 'application.argoproj.io': app}
        payload = {'operator': [self.desired], 'repository': 'public', 'branch': 'main',
                   'version': 'fixture', 'revision': 'published'}
        with tempfile.TemporaryDirectory() as folder, patch.object(bootstrap, 'BASE', Path(folder)), \
                patch.object(bootstrap, 'get', side_effect=lambda kind, _: objects[kind]), \
                patch.object(bootstrap, 'kube') as write, patch.object(bootstrap, 'wait_application') as wait, \
                patch.object(bootstrap, 'identity', return_value=self.state['identities']), \
                patch.object(bootstrap.subprocess, 'run', return_value=Mock(returncode=0, stdout='{"stable":true}')):
            (Path(folder) / 'checkpoint.json').write_text(json.dumps(self.state))
            result = bootstrap.recover_controller(payload)
            self.assertTrue(result['identities_preserved'])
            self.assertEqual(result['owner'], 'argocd')
            wait.assert_called_once_with('cloudlab-argocd', 'published')
            self.assertEqual([c.args[0] for c in write.call_args_list], ['annotate', 'patch', 'rollout'])
            write.reset_mock()
            with patch.object(bootstrap, 'identity', return_value={'secret/argocd-secret': 'replaced'}):
                with self.assertRaisesRegex(RuntimeError, 'credential identities'):
                    bootstrap.recover_controller(payload)
            write.assert_not_called()
            for field, value in (('project', 'foreign'), ('repoURL', 'foreign'), ('path', 'other'),
                                 ('targetRevision', 'unpublished')):
                bad = copy.deepcopy(app)
                if field == 'project': bad['spec'][field] = value
                else: bad['spec']['sources'][0][field] = value
                objects['application.argoproj.io'] = bad
                with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'accepted version or source'):
                    bootstrap.recover_controller(payload)
                write.assert_not_called()
