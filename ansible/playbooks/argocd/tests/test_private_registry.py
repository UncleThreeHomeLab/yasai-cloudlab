import copy
import base64
import json
from pathlib import Path
import subprocess
import unittest

import yaml
from fixtures import source_approval

from private_sources import PEM_TEMPLATE, registry, validate_registry, verification_payload

ROOT = Path(__file__).resolve().parents[4]
ENTRY = {'name': 'fixture', 'repository': 'https://github.com/example/private.git',
         'revision': 'main', 'path': 'gitops'}


class PrivateRegistryTests(unittest.TestCase):
    def symbolic_payload(self, rows, response):
        from unittest.mock import Mock, patch
        public = {'repository': 'https://github.com/example/platform.git',
                  'privateSources': {'enabled': True, 'revision': 'b' * 40},
                  'admission': {'enabled': True}, 'externalSecrets': {'enabled': True, 'reconcile': True}}
        approval = source_approval(public, ENTRY['repository'])
        raw = json.dumps({'sources': rows}).encode()
        contents = {'type': 'file', 'encoding': 'base64', 'size': len(raw), 'content': base64.b64encode(raw).decode()}
        def request(method, path):
            self.assertEqual(method, 'GET')
            if '/contents/platform/acceptance/private-sources.yaml?ref=' in path:
                receipt = json.dumps(approval['acceptanceReceipt']).encode()
                return {'type': 'file', 'encoding': 'base64', 'size': len(receipt), 'content': base64.b64encode(receipt).decode()}
            if '/contents/platform/sources.yaml?ref=' in path:
                self.assertTrue(path.endswith('d' * 40))
                return contents
            if isinstance(response, Exception): raise response
            return response(path) if callable(response) else response
        client = Mock(request=Mock(side_effect=request))
        def authenticated(values, *, read): return read(client, 'a' * 40)
        with patch('playbooks.argocd.files.github_app.configuration_revision', side_effect=authenticated):
            payload = verification_payload({'PRIVATE_CONFIG_REPOSITORY': ENTRY['repository']}, public)
        return payload, client

    def test_symbolic_refs_are_deduplicated_encoded_and_scoped_to_the_authenticated_repository(self):
        rows = [ENTRY, ENTRY | {'name': 'branch', 'revision': 'feature/prices'},
                ENTRY | {'name': 'branch-copy', 'revision': 'feature/prices'},
                ENTRY | {'name': 'tag', 'revision': 'release/v2'},
                ENTRY | {'name': 'pinned', 'revision': 'c' * 40},
                ENTRY | {'name': 'external', 'repository': 'https://github.com/example/other.git', 'revision': 'external/ref'}]
        commits = {'repos/example/private/commits/feature%2Fprices': {'sha': 'b' * 40},
                   'repos/example/private/commits/release%2Fv2': {'sha': 'd' * 40}}
        payload, client = self.symbolic_payload(rows, lambda path: commits[path])
        self.assertEqual(payload['symbolic_revisions'], {'feature/prices': 'b' * 40, 'release/v2': 'd' * 40})
        self.assertEqual(payload['configuration_revision'], 'a' * 40)
        self.assertEqual([call.args[1] for call in client.request.call_args_list if '/commits/' in call.args[1]], list(commits))
        branch = next(obj for obj in payload['objects'] if obj['kind'] == 'Application' and obj['metadata']['name'].endswith('-branch'))
        self.assertEqual(branch['spec']['source']['targetRevision'], 'feature/prices')

    def test_symbolic_ref_api_failure_and_malformed_sha_are_generic_failures(self):
        for response in (RuntimeError('private diagnostic must not escape'), None, {}, {'sha': None},
                         {'sha': 'main'}, {'sha': 'A' * 40}):
            with self.subTest(response=response), self.assertRaisesRegex(ValueError, '^Private source symbolic revision') as failure:
                self.symbolic_payload([ENTRY | {'revision': 'release/v2'}], response)
            self.assertNotIn('private diagnostic', str(failure.exception))

    def test_verification_reads_and_renders_the_same_authenticated_complete_revision(self):
        from unittest.mock import Mock, patch
        public = {'repository': 'https://github.com/example/platform.git',
                  'privateSources': {'enabled': True, 'revision': 'b' * 40},
                  'admission': {'enabled': True}, 'externalSecrets': {'enabled': True, 'reconcile': True}}
        approval = source_approval(public, ENTRY['repository'])
        client = Mock()
        def read(method, path):
            raw = json.dumps(approval['acceptanceReceipt']).encode() if '/acceptance/' in path else b'sources: []\n'
            return {'type': 'file', 'encoding': 'base64', 'size': len(raw), 'content': base64.b64encode(raw).decode()}
        client.request.side_effect = read
        def authenticated(values, *, read): return read(client, 'a' * 40)
        with patch('playbooks.argocd.files.github_app.configuration_revision', side_effect=authenticated):
            payload = verification_payload({'PRIVATE_CONFIG_REPOSITORY': ENTRY['repository']}, public)
        self.assertEqual(payload['sources'], [])
        self.assertEqual(payload['objects'], [])
        self.assertEqual(payload['configuration_revision'], 'a' * 40)
        self.assertTrue(client.request.call_args.args[1].endswith('?ref=' + 'd' * 40))
        for stale in ({'PRIVATE_GITOPS_SOURCES': '[{}]'}, {'PRIVATE_GITOPS_REMOVE': 'example'}):
            with self.assertRaisesRegex(ValueError, 'Legacy private source inputs'):
                registry(client, dict(stale, PRIVATE_CONFIG_REPOSITORY=ENTRY['repository']), public, 'd' * 40, acceptance=approval)
    def render(self, value, success=True):
        result = subprocess.run(['helm', 'template', 'private-sources',
            str(ROOT / 'platform/delivery/private-sources'), '-n', 'argocd', '-f', '-'],
            input=json.dumps(value), capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return [obj for obj in yaml.safe_load_all(result.stdout) if obj] if success else []

    def test_explicit_empty_is_valid_but_missing_or_invalid_input_cannot_become_empty(self):
        self.assertEqual(self.render({'sources': []}), [])
        for value in ({}, {'sources': None}, {'sources': {}}, {'sources': False}, {'sources': [False]},
                      {'sources': [], 'unknown': True}, {'sources': [ENTRY] * 21}):
            with self.subTest(value=value): self.render(value, False)

    def test_unsafe_duplicate_reserved_or_expanded_entries_are_refused(self):
        self.render({'sources': [ENTRY, ENTRY]}, False)
        for change in ({'name': 'sources'}, {'name': 'sources-source'}, {'name': '../argocd'},
                       {'repository': 'https://token@github.com/example/private.git'},
                       {'path': '../escape'}, {'path': 'inside/../escape'}, {'path': '/absolute'},
                       {'revision': '-flag'}, {'namespace': 'argocd'}):
            with self.subTest(change=change): self.render({'sources': [ENTRY | change]}, False)

    def test_native_declarations_preserve_isolation_credentials_and_retention(self):
        objects = sorted(self.render({'sources': [ENTRY]}), key=lambda obj:
                         int(obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/sync-wave', '0')))
        self.assertEqual([obj['kind'] for obj in objects], ['Namespace', 'AppProject', 'ExternalSecret', 'Application'])
        namespace, project, credential, app = objects
        name = 'cloudlab-private-fixture'
        self.assertEqual([obj['metadata']['name'] for obj in objects], [name] * 4)
        self.assertEqual(namespace['metadata']['annotations']['argocd.argoproj.io/sync-options'], 'Prune=false,Delete=false')
        self.assertEqual(namespace['metadata']['annotations']['argocd.argoproj.io/compare-options'], 'IgnoreExtraneous')
        self.assertEqual(project['spec']['sourceRepos'], [ENTRY['repository']])
        self.assertEqual(project['spec']['destinations'], [{'server': 'https://kubernetes.default.svc', 'namespace': name}])
        self.assertEqual(project['spec']['clusterResourceWhitelist'], [])
        self.assertFalse({'Secret', 'Role', 'RoleBinding', 'Application', 'AppProject', 'ExternalSecret', 'Gateway'} &
                         {row['kind'] for row in project['spec']['namespaceResourceWhitelist']})
        self.assertEqual(credential['spec']['target']['template']['data']['githubAppPrivateKey'], PEM_TEMPLATE)
        self.assertEqual(credential['spec']['target']['template']['data']['project'], name)
        self.assertEqual(credential['spec']['dataFrom'], [{'extract': {'key': 'github-argocd'}}])
        self.assertEqual(credential['spec']['target']['creationPolicy'], 'Owner')
        self.assertEqual(credential['spec']['target']['deletionPolicy'], 'Retain')
        self.assertFalse(app['spec']['syncPolicy']['automated']['prune'])
        self.assertNotIn('finalizers', app['metadata'])
        self.assertEqual(app['spec']['source'], {'repoURL': ENTRY['repository'], 'targetRevision': 'main', 'path': 'gitops'})
        waves = [int(obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/sync-wave', '0')) for obj in objects]
        self.assertEqual(waves, sorted(set(waves)))

    def test_disabled_reader_does_not_fetch_or_require_registry_inputs(self):
        class RefuseRead:
            def request(self, *args): raise AssertionError('Disabled registry must not read Git')
        self.assertIsNone(registry(RefuseRead(), {}, {'privateSources': {'enabled': False}}, 'not-a-sha'))
        with self.assertRaises(ValueError): registry(RefuseRead(), {}, {'privateSources': {'enabled': 'false'}}, 'a' * 40)

    def test_native_input_validation_refuses_missing_or_unbounded_values(self):
        self.assertEqual(validate_registry({'sources': []}), {'sources': []})
        with self.assertRaises(ValueError): validate_registry({})
        with self.assertRaises(ValueError): validate_registry({'sources': [ENTRY | {'name': 'sources'}]})

    def test_reader_rejects_nonregular_and_missing_complete_yaml(self):
        from unittest.mock import Mock
        public = {'privateSources': {'enabled': True}, 'admission': {'enabled': True},
                  'externalSecrets': {'enabled': True, 'reconcile': True}}
        approval = source_approval(public, ENTRY['repository'], 'a' * 40)
        values = {'PRIVATE_CONFIG_REPOSITORY': ENTRY['repository']}
        document = {'type': 'file', 'encoding': 'base64', 'size': 3,
                    'content': base64.b64encode(b'{}\n').decode()}
        for change in ({}, {'type': 'symlink'}, {'encoding': 'none'}, {'size': 1048577}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                registry(Mock(request=Mock(return_value=document | change)), values, public, 'a' * 40, acceptance=approval)
