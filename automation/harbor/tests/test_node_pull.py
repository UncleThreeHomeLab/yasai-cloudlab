import base64
import json
import os
from pathlib import Path
import subprocess
import tomllib
import unittest
from unittest.mock import Mock, patch

from automation.harbor import node_pull


class NodePullTests(unittest.TestCase):
    def test_both_nodes_receive_only_each_project_pull_credential_over_standard_input(self):
        client = Mock()
        client.values = {prefix + '_' + name: value for prefix in ('VM', 'VM2')
                         for name, value in (('HOST', '192.0.2.1'), ('USER', 'fixture'), ('PASSWORD', 'synthetic-ssh'))}
        robots = {project + '-' + role: {'username': 'robot$' + project + '+' + role,
                    'password': project + '-' + role + '-synthetic', 'extra': 'must-not-be-delivered'}
                  for project in ('cloudlab-public', 'cloudlab-private') for role in ('pull', 'push')}
        client.private = {'host': 'harbor.internal.example.invalid', 'robots': robots}
        recorded = {'projects': {project: {'digest': 'sha256:' + 'a' * 64}
                                for project in ('cloudlab-public', 'cloudlab-private')}}
        received = []
        def ssh(prefix, host, command, **kwargs):
            data = json.loads(kwargs['input'])
            self.assertEqual(set(data), {'host', 'project', 'digest', 'username', 'password'})
            self.assertEqual(data['username'], 'robot$' + data['project'] + '+pull')
            self.assertNotIn(data['password'], command)
            received.append((prefix, data['project']))
            return json.dumps({'host_dns_tls': True, 'containerd_pull_by_digest': True, 'temporary_credentials_removed': True})
        with patch.dict(os.environ), patch('automation.connectivity.preflight.ssh', side_effect=ssh):
            self.assertEqual(node_pull.verify_nodes(client, recorded), 4)
        self.assertEqual(set(received), {(prefix, project) for prefix in ('VM', 'VM2') for project in recorded['projects']})

    def payload(self):
        return {'host': 'harbor.internal.example.invalid', 'project': 'cloudlab-public',
                'username': 'robot$cloudlab-public+pull', 'password': 'synthetic-' + 'x' * 48,
                'digest': 'sha256:' + 'a' * 64}

    def test_token_requires_exact_read_scope_and_five_minute_lifetime(self):
        payload = self.payload()
        access = [{'type': 'repository', 'name': 'cloudlab-public/bootstrap', 'actions': ['pull']}]
        for changes, accepted in (({}, True), ({'aud': ['harbor-registry']}, True),
                ({'access': [dict(access[0], actions=['pull', 'push'])]}, False),
                ({'exp': 4600}, False), ({'aud': 'other-service'}, False)):
            claims = dict({'access': access, 'aud': 'harbor-registry', 'exp': 1300}, **changes)
            encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
            token = 'e30.' + encoded + '.c2ln'
            connection = Mock()
            response = connection.getresponse.return_value
            response.status, response.read.return_value = 200, json.dumps({'token': token}).encode()
            with self.subTest(changes=changes), patch.object(node_pull.time, 'time', return_value=1000), \
                    patch.object(node_pull.http.client, 'HTTPSConnection', return_value=connection) as connect:
                if accepted:
                    self.assertEqual(node_pull.token(payload), token)
                else:
                    with self.assertRaises(RuntimeError): node_pull.token(payload)
                connect.assert_called_once_with(payload['host'], timeout=20)
                self.assertIn('scope=repository%3Acloudlab-public%2Fbootstrap%3Apull', connection.request.call_args.args[1])
                connection.close.assert_called_once()

    def test_node_accepts_only_scoped_pull_credentials_and_digest_references(self):
        for changes in ({'username': 'robot$cloudlab-public+push'}, {'digest': 'latest'},
                        {'host': 'harbor.internal.example.invalid/other'}, {'project': 'other/project'}):
            with self.subTest(changes=changes), patch.object(node_pull.http.client, 'HTTPSConnection') as connect:
                with self.assertRaises(ValueError): node_pull.token(dict(self.payload(), **changes))
                connect.assert_not_called()

    def test_success_and_timeout_clean_only_owned_containerd_namespace_and_credentials(self):
        for interrupted in (False, True):
            paths, namespaces, snapshots = [], set(), {'parent', 'child'}
            payload = self.payload()
            def command(arguments, **kwargs):
                self.assertNotIn(payload['password'], arguments)
                self.assertNotIn('synthetic-short-token', arguments)
                namespace, action = arguments[3], arguments[4:]
                self.assertTrue(namespace.startswith('cloudlab-harbor-proof-'))
                namespaces.add(namespace)
                code, output = 0, b''
                if action[:2] == ['images', 'pull']:
                    directory = Path(action[action.index('--hosts-dir') + 1])
                    paths.append(directory)
                    path = directory / payload['host'] / 'hosts.toml'
                    settings = tomllib.loads(path.read_text())
                    self.assertEqual(settings['host']['https://' + payload['host']]['header']['authorization'], ['Bearer synthetic-short-token'])
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertIn('--local', action)
                    self.assertTrue(action[-1].endswith('@' + payload['digest']))
                    if interrupted: raise subprocess.TimeoutExpired(arguments, 180)
                elif action[:2] == ['snapshots', 'list']:
                    output = ('\n'.join(sorted(snapshots)) + '\n').encode() if snapshots else b''
                elif action[:2] == ['snapshots', 'remove']:
                    key = action[2]
                    if key == 'parent' and 'child' in snapshots: code = 1
                    else: snapshots.discard(key)
                elif action[:2] == ['namespaces', 'remove']:
                    self.assertFalse(snapshots)
                    self.assertEqual(action[2], namespace)
                return subprocess.CompletedProcess(arguments, code, output, b'')
            with self.subTest(interrupted=interrupted), patch.object(node_pull, 'token', return_value='synthetic-short-token'), \
                    patch.object(node_pull.subprocess, 'run', side_effect=command):
                if interrupted:
                    with self.assertRaises(subprocess.TimeoutExpired): node_pull.run(payload)
                else:
                    self.assertTrue(node_pull.run(payload)['containerd_pull_by_digest'])
                self.assertEqual(len(namespaces), 1)
                self.assertTrue(all(not path.exists() for path in paths))
