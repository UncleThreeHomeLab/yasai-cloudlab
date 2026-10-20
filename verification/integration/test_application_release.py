"""Disposable enforcement cannot affect production names or treat auth failures as signature proof."""
import copy
import subprocess
import unittest
from unittest.mock import Mock, patch

from verification.integration import application_release as proof


def policy():
    return {'apiVersion': 'kyverno.io/v1', 'kind': 'Policy', 'metadata': {
        'name': 'application-artifacts', 'namespace': 'cloudlab-app-example', 'uid': 'production',
        'resourceVersion': '123', 'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-services:policy'},
        'labels': {'argocd.argoproj.io/instance': 'cloudlab-services'}}, 'status': {'ready': True},
        'spec': {'validationFailureAction': 'Audit', 'background': False, 'rules': [
            {'name': 'approved-repositories', 'match': {'any': [{'resources': {'kinds': ['Pod']}}]},
             'validate': {'message': 'Repository denied'}},
            {'name': 'trusted-signature', 'match': {'any': [{'resources': {'kinds': ['Pod']}}]},
             'verifyImages': [{'imageReferences': ['registry.example.invalid/cloudlab-public/example@sha256:*']}]}]}}


class ApplicationReleaseTests(unittest.TestCase):
    def test_public_pool_rejects_private_vault_items_secret_readers_and_expanded_build_quota(self):
        externals = [{'spec': {'secretStoreRef': {'name': 'cloudlab', 'kind': 'ClusterSecretStore'},
                              'dataFrom': [{'extract': {'key': key}}]}} for key in
                     ('github-arc-public', 'harbor-cloudlab-public-pull', 'harbor-cloudlab-public-push', 'github-release-public')]
        sets = {'items': [{'spec': {'maxRunners': 1, 'template': {'spec': {'serviceAccountName': 'cloudlab-ci-health'}}}}] * 2}
        quota = {'spec': {'hard': {'pods': '1', 'limits.cpu': '3', 'limits.memory': '6Gi'}}}
        def get(kind, name=None, namespace=None):
            if kind == 'namespace':
                return {'items': [{'metadata': {'name': name}} for name in
                                  ('cloudlab-ci-public-example', 'cloudlab-ci-private-example')]}
            self.assertEqual(namespace, 'cloudlab-ci-public-example')
            if kind.startswith('autoscalingrunnersets'): return sets
            if kind == 'resourcequota':
                self.assertEqual(name, 'runner-budget')
                return quota
            if kind == 'externalsecrets': return {'items': externals}
            raise AssertionError(kind)
        denied = subprocess.CompletedProcess([], 1, 'no\n', '')
        with patch('playbooks.istio.files.kube.get', side_effect=get), \
                patch('playbooks.istio.files.kube.kube', return_value=denied) as kube:
            proof.public_pool({'name': 'example'})
            self.assertEqual(kube.call_count, 2)
            self.assertIn('--as=system:serviceaccount:cloudlab-ci-public-example:cloudlab-ci-health', kube.call_args.args)
            self.assertIn('--as-group=system:serviceaccounts:cloudlab-ci-public-example', kube.call_args.args)
            self.assertIn('cloudlab-ci-private-example', kube.call_args.args)
            externals[-1]['spec']['dataFrom'][0]['extract']['key'] = 'github-release-private'
            with self.assertRaises(RuntimeError): proof.public_pool({'name': 'example'})
            externals[-1]['spec']['dataFrom'][0]['extract']['key'] = 'github-release-public'
            quota['spec']['hard']['pods'] = '2'
            with self.assertRaises(RuntimeError): proof.public_pool({'name': 'example'})
            quota['spec']['hard']['pods'] = '1'
            kube.return_value = subprocess.CompletedProcess([], 0, 'yes\n', '')
            with self.assertRaises(RuntimeError): proof.public_pool({'name': 'example'})

    def test_enforcement_fixture_preserves_production_and_matches_only_its_exact_name_and_nonce(self):
        production = policy()
        original = copy.deepcopy(production)
        fixture = proof.isolated_policy(production, 'artifact-proof-' + 'a' * 12, 'a' * 12)
        self.assertEqual(production, original)
        self.assertEqual(fixture['spec']['validationFailureAction'], 'Enforce')
        self.assertNotIn('status', fixture)
        self.assertNotIn('uid', fixture['metadata'])
        self.assertNotIn('resourceVersion', fixture['metadata'])
        self.assertNotIn('argocd.argoproj.io/tracking-id', fixture['metadata']['annotations'])
        for rule in fixture['spec']['rules']:
            self.assertEqual(rule['match']['any'][0]['resources'], {'kinds': ['Pod'],
                'names': ['artifact-proof-' + 'a' * 12],
                'selector': {'matchLabels': {'cloudlab.io/release-proof': 'a' * 12}}})

    def exercise(self, *, unauthorized=False, ignored=False, previous=None):
        production = policy()
        store = {}
        calls = []
        def get(kind, name, namespace):
            if name == 'application-artifacts': return production
            return store.get('policy', previous)
        def kube(*arguments, **options):
            calls.append((arguments, copy.deepcopy(options)))
            if arguments == ('create', '-f', '-'):
                document = copy.deepcopy(options['document'])
                self.assertEqual(document['kind'], 'Policy')
                document['metadata']['uid'] = 'owned-proof'
                document['status'] = {'ready': True}
                store['policy'] = document
                return ''
            if arguments[0] == 'delete':
                self.assertEqual(arguments[1:3], ('policy.kyverno.io', 'artifact-release-proof'))
                store['policy'] = None
                return ''
            self.assertEqual(arguments[:2], ('create', '--dry-run=server'))
            pod = options['document']
            self.assertEqual(pod['kind'], 'Pod')
            self.assertEqual(pod['spec']['imagePullSecrets'], [{'name': 'harbor-application-pull'}])
            self.assertEqual(pod['metadata']['labels'], {'cloudlab.io/release-proof': 'a' * 12})
            image = pod['spec']['containers'][0]['image']
            if image == 'signed' or ignored:
                return subprocess.CompletedProcess(arguments, 0, '', '')
            rule = 'approved-repositories' if image == 'other' else 'trusted-signature'
            return subprocess.CompletedProcess(arguments, 1, '', rule + (' UNAUTHORIZED' if unauthorized else ' signature not found'))
        request = {'entry': {'approval': {'namespace': 'cloudlab-app-example', 'artifact': {'action': 'Audit'}}},
                   'action': 'admission', 'images': [
                       ['signed', 'signed', None], ['unsigned', 'unsigned', 'trusted-signature'],
                       ['untrusted', 'untrusted', 'trusted-signature'], ['other', 'other', 'approved-repositories']]}
        with patch('playbooks.istio.files.kube.get', side_effect=get), \
                patch('playbooks.istio.files.kube.kube', side_effect=kube), \
                patch('playbooks.istio.files.kube.wait', side_effect=lambda predicate, *args, **kwargs: self.assertTrue(predicate())), \
                patch.object(proof.secrets, 'token_hex', return_value='a' * 12):
            try:
                result = proof.remote(request)
            finally:
                self.assertEqual(production['spec']['validationFailureAction'], 'Audit')
        return result, calls

    def test_signature_denial_proof_creates_only_policy_and_server_dry_runs_then_removes_its_policy(self):
        result, calls = self.exercise()
        self.assertEqual(result['test_pods_created'], 0)
        self.assertTrue(result['signed_admitted'] and result['unsigned_denied'] and result['untrusted_signer_denied'])
        self.assertEqual(sum(arguments[:2] == ('create', '--dry-run=server') for arguments, _ in calls), 4)
        self.assertEqual(calls[-1][0][0], 'delete')

    def test_registry_auth_failure_or_ignored_policy_never_counts_as_unsigned_rejection(self):
        for options in ({'unauthorized': True}, {'ignored': True}):
            with self.subTest(options=options), self.assertRaises(RuntimeError):
                self.exercise(**options)

    def test_retained_foreign_policy_is_never_deleted_or_replaced(self):
        previous = proof.isolated_policy(policy(), 'artifact-proof-' + 'b' * 12, 'b' * 12)
        previous['metadata']['labels']['cloudlab.io/owner'] = 'other-owner'
        with self.assertRaisesRegex(RuntimeError, 'cleanup refused'):
            self.exercise(previous=previous)

    def test_registry_credentials_cannot_be_sent_to_a_catalog_host_different_from_accepted_harbor(self):
        client = Mock()
        client.private = {'host': 'registry.example.invalid'}
        entry = {'approval': {'name': 'example', 'artifact': {
            'project': 'cloudlab-public', 'repository': 'foreign.example.invalid/cloudlab-public/example'}}}
        with patch.object(proof, 'on_node') as on_node, self.assertRaises(ValueError):
            proof.prove(client, entry)
        on_node.assert_not_called()
