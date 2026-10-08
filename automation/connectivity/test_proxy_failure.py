"""A crash fixture must never signal unrelated or reused host processes."""
import copy
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from automation.connectivity import proxy_failure


class ProxyCrashTests(unittest.TestCase):
    def setUp(self):
        self.payload = {'name': 'cloudlab-ingress-0', 'uid': 'pod-uid', 'container_id': 'a' * 64}
        self.container = {'status': {'id': 'a' * 64, 'state': 'CONTAINER_RUNNING',
            'metadata': {'name': 'tailscale'}, 'labels': {
                'io.kubernetes.pod.namespace': 'tailscale',
                'io.kubernetes.pod.name': 'cloudlab-ingress-0',
                'io.kubernetes.pod.uid': 'pod-uid'}}, 'info': {'pid': 1234}}

    def test_other_namespace_pod_identity_or_container_cannot_be_targeted(self):
        for field, value in [('io.kubernetes.pod.namespace', 'kube-system'),
                             ('io.kubernetes.pod.name', 'cloudlab-api-0'),
                             ('io.kubernetes.pod.uid', 'replacement-uid')]:
            container = copy.deepcopy(self.container)
            container['status']['labels'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                proxy_failure.validate(self.payload, container)
        for field, value in [('id', 'b' * 64), ('state', 'CONTAINER_EXITED'),
                             ('metadata', {'name': 'kube-apiserver'})]:
            container = copy.deepcopy(self.container)
            container['status'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                proxy_failure.validate(self.payload, container)

    def test_cgroup_mismatch_refuses_signal_and_closes_pid_descriptor(self):
        with patch.object(proxy_failure.subprocess, 'run', return_value=SimpleNamespace(stdout=json.dumps(self.container))), \
                patch.object(proxy_failure.os, 'pidfd_open', return_value=7), \
                patch.object(proxy_failure.Path, 'read_text', return_value='another-container'), \
                patch.object(proxy_failure.signal, 'pidfd_send_signal') as send, \
                patch.object(proxy_failure.os, 'close') as close:
            with self.assertRaises(RuntimeError): proxy_failure.run(self.payload)
            send.assert_not_called()
            close.assert_called_once_with(7)

    def test_host_init_and_invalid_container_ids_refuse_signal(self):
        self.container['info']['pid'] = 1
        with patch.object(proxy_failure.subprocess, 'run', return_value=SimpleNamespace(stdout=json.dumps(self.container))), \
                patch.object(proxy_failure.os, 'pidfd_open') as pidfd:
            with self.assertRaises(RuntimeError): proxy_failure.run(self.payload)
            pidfd.assert_not_called()
        self.payload['container_id'] = '--help'
        with patch.object(proxy_failure.subprocess, 'run') as run:
            with self.assertRaises(RuntimeError): proxy_failure.run(self.payload)
            run.assert_not_called()
