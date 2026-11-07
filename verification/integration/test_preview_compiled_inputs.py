"""Preview requests compile into bounded disposable lifecycle ownership.

A reviewed prices YAML approval request validates against the approval
schema, derives its deterministic instance and namespace ownership
through requested_catalog, renders the controller chart, and retires
through the same guarded path when its request is removed or expires.
"""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml
from jsonschema import validate
from jsonschema.exceptions import ValidationError

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'platform/delivery/previews/runtime'))

import contract
import lifecycle

SCHEMA = json.loads(
    (ROOT / 'platform/delivery/previews/approval.schema.json').read_text())

IMAGE = ('harbor.example.test/cloudlab-public/prices@sha256:' + 'd' * 64)
NOW = 1790000000


def prices_request(**overrides):
    request = {
        'service': 'prices',
        'repository': 'example/prices',
        'repositoryId': 123456,
        'pullRequest': 42,
        'sourceRevision': 'e' * 40,
        'image': IMAGE,
        'platformRevision': 'f' * 40,
        'profile': 'application',
        'definition': {
            'profile': 'application',
            'port': 8080,
            'healthPath': '/healthz',
            'environment': {'PREVIEW_MODE': 'synthetic'},
            'resources': {
                'requests': {'cpu': '50m', 'memory': '64Mi'},
                'limits': {'cpu': '100m', 'memory': '128Mi'}}},
        'createdAt': NOW - 60,
        'expiresAt': NOW + 3540}
    request.update(overrides)
    return request


def catalog(*requests):
    return {
        'hostname': 'previews.internal.example.test',
        'issuer': 'https://login.example.test/realms/applications',
        'approvals': [],
        'privateDiscovery': False,
        'ownership': {},
        'artifacts': {
            'harbor.example.test/cloudlab-public/prices': {
                'subject': 'https://github.com/example/prices/.github/workflows/ci.yaml@refs/heads/main',
                'issuer': 'https://token.actions.githubusercontent.com',
                'sourceRepository': 'example/prices',
                'public': True}},
        'requests': list(requests)}


def render(values):
    if shutil.which('helm') is None:
        raise unittest.SkipTest('helm renders the preview controller chart')
    with tempfile.TemporaryDirectory() as workspace:
        work = Path(workspace)
        (work / 'values.yaml').write_text(yaml.safe_dump(values))
        rendered = subprocess.check_output(
            ['helm', 'template', '--kube-version', '1.36',
             '-f', str(work / 'values.yaml'),
             str(ROOT / 'platform/delivery/previews')],
            text=True, timeout=120, stderr=subprocess.STDOUT)
    return [doc for doc in yaml.safe_load_all(rendered) if doc]


def root_with(values):
    if shutil.which('helm') is None:
        raise unittest.SkipTest('helm renders the public root')
    rendered = subprocess.check_output(
        ['helm', 'template', 'root', str(ROOT / 'gitops/roots/public'), '-f', '-'],
        input=json.dumps(values), text=True, timeout=120)
    return [doc for doc in yaml.safe_load_all(rendered) if doc]


def root_fails(values):
    if shutil.which('helm') is None:
        raise unittest.SkipTest('helm renders the public root')
    result = subprocess.run(
        ['helm', 'template', 'root', str(ROOT / 'gitops/roots/public'), '-f', '-'],
        input=json.dumps(values), capture_output=True, text=True, timeout=60)
    return result.returncode != 0


def previews_commitment(repository, revision, nonce,
                        paths=('previews/catalog.yaml',)):
    preimage = '\n'.join(['cloudlab-consumer-source-acceptance/v1', 'previews',
                          repository, str(len(paths)), *paths, revision, nonce, ''])
    return hashlib.sha256(preimage.encode()).hexdigest()


def enabled_writer(**overrides):
    configuration = {'enabled': True, 'revision': 'a' * 40,
                     'acceptanceCommitment': '1' * 64, 'permissionsEnabled': False}
    configuration.update(overrides)
    return {'identity': {'argo': {
        'valuesRepository': 'https://github.com/example/private.git',
        'valuesRevision': 'b' * 40}},
        'previews': {'configuration': configuration}}


def observed_pull(state='open', sha='e' * 40, draft=False, fork=False,
                  number=42, base_id=123456, base_name='example/prices',
                  head_id=123456, head_name='example/prices'):
    return {'number': number, 'state': state, 'draft': draft,
            'base': {'repo': {'id': base_id, 'full_name': base_name}},
            'head': {'repo': {'id': head_id, 'full_name': head_name, 'fork': fork},
                     'sha': sha}}


class PreviewCompiledInputsTests(unittest.TestCase):
    def test_request_derives_deterministic_instance_and_ownership(self):
        request = prices_request()
        validate(request, SCHEMA)
        merged = contract.requested_catalog(catalog(request))
        settings = contract.runtime_catalog(merged)
        self.assertEqual(len(settings['approvals']), 1)
        row = settings['approvals'][0]
        self.assertEqual(row['instance'],
                         contract.digest(contract.canonical(request))[:32])
        self.assertEqual(row['sourceSha'], 'e' * 40)
        self.assertEqual(row['sourcePath'], 'previews/definition.json')
        self.assertEqual(
            row['sourceDigest'],
            contract.digest(contract.canonical(request['definition'])))
        # Identical content reuses its instance; any change enrolls a new one.
        again = contract.requested_catalog(catalog(prices_request()))
        self.assertEqual(again['approvals'][0]['instance'], row['instance'])
        changed = contract.requested_catalog(
            catalog(prices_request(pullRequest=43)))
        self.assertNotEqual(changed['approvals'][0]['instance'], row['instance'])
        namespace = 'cloudlab-preview-' + row['instance']
        self.assertEqual(settings['ownership'][namespace],
                         row['instance'] + ':' + contract.digest(
                             contract.canonical(row)))

    def test_rendered_controller_carries_catalog_and_stays_suspended(self):
        settings = contract.runtime_catalog(
            contract.requested_catalog(catalog(prices_request())))
        documents = render({
            'enabled': True,
            'permissionsEnabled': False,
            'platformRepository': 'https://github.com/example/platform.git',
            'catalog': settings})
        approvals = next(doc for doc in documents
                         if doc.get('kind') == 'ConfigMap'
                         and doc['metadata']['name'] == 'cloudlab-preview-approvals')
        self.assertEqual(json.loads(approvals['data']['catalog.json']), settings)
        code = next(doc for doc in documents
                    if doc.get('kind') == 'ConfigMap'
                    and doc['metadata']['name'] == 'cloudlab-preview-code')
        self.assertIn('controller.py', code['data'])
        cron = next(doc for doc in documents if doc.get('kind') == 'CronJob')
        self.assertIs(cron['spec']['suspend'], True)
        pod = cron['spec']['jobTemplate']['spec']['template']['spec']
        self.assertEqual(pod['serviceAccountName'], 'cloudlab-previews')
        self.assertEqual(pod['containers'][0]['image'], contract.IMAGE)

    def test_removed_or_expired_requests_retire_without_reactivation(self):
        row = contract.request(prices_request())
        state = lifecycle.enroll({'entries': {}}, row, NOW)
        record = state['entries'][row['instance']]
        record['phase'] = 'active'
        # Removing the accepted request retires; expiry retires even if kept.
        self.assertEqual(lifecycle.retirement(row, None, None, NOW), 'orphan')
        self.assertEqual(
            lifecycle.retirement(row, row, None, row['expiresAt']), 'expired')
        # Re-enrollment after retirement never reactivates the instance.
        retired = dict(record, phase='retired')
        kept = lifecycle.enroll({'entries': {row['instance']: retired}}, row, NOW)
        self.assertEqual(kept['entries'][row['instance']]['phase'], 'retired')

    def test_invalid_requests_fail_schema_or_contract(self):
        with self.assertRaises(ValidationError):
            validate(prices_request(sourceRevision='main'), SCHEMA)
        with self.assertRaises(ValueError):
            contract.request(prices_request(sourceRevision='main'))
        short = prices_request(expiresAt=NOW - 31)
        with self.assertRaises(ValueError):
            contract.request(short)
        oversized = catalog(*[prices_request(pullRequest=n) for n in range(1, 22)])
        with self.assertRaises(ValueError):
            contract.requested_catalog(oversized)

    def test_exact_open_revision_proceeds_while_stale_foreign_closed_deny(self):
        row = contract.request(prices_request())
        self.assertIsNone(lifecycle.retirement(row, row, observed_pull(), NOW))
        self.assertEqual(
            lifecycle.retirement(row, row, observed_pull(state='closed'), NOW),
            'closed')
        for pull in (observed_pull(sha='a' * 40), observed_pull(draft=True),
                     observed_pull(fork=True),
                     observed_pull(head_id=999, head_name='example/fork')):
            with self.subTest(pull=pull):
                self.assertEqual(lifecycle.retirement(row, row, pull, NOW),
                                 'revision-unapproved')
        for pull in (observed_pull(number=43),
                     observed_pull(base_name='example/other'),
                     observed_pull(state='unknown')):
            with self.subTest(pull=pull):
                with self.assertRaises(ValueError):
                    lifecycle.retirement(row, row, pull, NOW)

    def test_disabled_configuration_writes_no_approval_ingress(self):
        rows = root_with({})
        self.assertFalse(any(row['kind'] == 'ApplicationSet'
                             and row['metadata']['name'] == 'cloudlab-previews'
                             for row in rows))
        bound = enabled_writer(enabled=False)
        rows = root_with(bound)
        self.assertFalse(any(row['kind'] == 'ApplicationSet'
                             and row['metadata']['name'] == 'cloudlab-previews'
                             for row in rows))

    def test_enabled_writer_feeds_private_catalog_behind_accepted_revision(self):
        rows = root_with(enabled_writer())
        self.assertFalse(any(row['kind'] == 'Application'
                             and row['metadata']['name'] == 'cloudlab-previews'
                             for row in rows))
        parent = next(row for row in rows
                      if row['kind'] == 'ApplicationSet'
                      and row['metadata']['name'] == 'cloudlab-previews')
        self.assertEqual(parent['metadata']['labels']['cloudlab.io/owner'],
                         'preview-platform')
        self.assertEqual(parent['spec']['goTemplateOptions'], ['missingkey=error'])
        self.assertEqual(parent['spec']['syncPolicy'],
                         {'applicationsSync': 'create-update',
                          'preserveResourcesOnDeletion': True})
        generators = parent['spec']['generators'][0]['merge']['generators']
        self.assertEqual(generators[0], {'list': {'elements': [{'consumer': 'previews'}]}})
        self.assertEqual(generators[1], {'git': {
            'repoURL': 'https://github.com/example/private.git', 'revision': 'main',
            'files': [{'path': 'platform/acceptance/previews.yaml'}]}})
        application = parent['spec']['template']
        self.assertEqual(application['metadata']['labels']['cloudlab.io/owner'],
                         'preview-platform')
        self.assertEqual(application['metadata']['annotations']['argocd.argoproj.io/tracking-id'],
                         'cloudlab-public-root:argoproj.io/Application:argocd/cloudlab-previews')
        self.assertEqual(application['spec']['project'], 'cloudlab-previews')
        chart, values = application['spec']['sources']
        self.assertEqual(chart['repoURL'],
                         'https://github.com/UncleThreeHomeLab/yasai-cloudlab.git')
        self.assertEqual(chart['targetRevision'], 'a' * 40)
        self.assertEqual(chart['path'], 'platform/delivery/previews')
        self.assertEqual(chart['helm']['valueFiles'], ['$values/previews/catalog.yaml'])
        self.assertEqual(chart['helm']['valuesObject'],
                         {'enabled': True, 'permissionsEnabled': False,
                          'platformRepository': 'https://github.com/UncleThreeHomeLab/yasai-cloudlab.git'})
        self.assertEqual(values['repoURL'], 'https://github.com/example/private.git')
        self.assertEqual(values['ref'], 'values')
        self.assertIn('Consumer source acceptance refused', values['targetRevision'])
        self.assertIn('"previews"', values['targetRevision'])
        self.assertIn('previews/catalog.yaml', values['targetRevision'])
        self.assertIn('1' * 64, values['targetRevision'])
        self.assertEqual(application['spec']['destination'],
                         {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'})
        self.assertEqual(application['spec']['syncPolicy']['automated'],
                         {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False})
        self.assertIn('FailOnSharedResource=true',
                      application['spec']['syncPolicy']['syncOptions'])

    def test_writer_rejects_unreviewed_revision_or_commitment(self):
        for bad in ('', 'main', 'a' * 39):
            with self.subTest(revision=bad):
                self.assertTrue(root_fails(enabled_writer(revision=bad)))
        for bad in ('', '1' * 63, True):
            with self.subTest(commitment=bad):
                self.assertTrue(root_fails(enabled_writer(acceptanceCommitment=bad)))
        self.assertTrue(root_fails(enabled_writer(permissionsEnabled='false')))
        self.assertTrue(root_fails({'previews': {'configuration': {'enabled': 'true'}}}))

    def test_acceptance_commitment_binds_exact_private_revision(self):
        commitment = previews_commitment('https://github.com/example/private.git',
                                         'a' * 40, 'b' * 64)
        self.assertEqual(commitment,
                         'ee04a45dfb3d81a69f537c8610e47b599e39cc06605c3fa093297a1d03945018')
        for changed in (previews_commitment('https://github.com/example/other.git', 'a' * 40, 'b' * 64),
                        previews_commitment('https://github.com/example/private.git', 'c' * 40, 'b' * 64),
                        previews_commitment('https://github.com/example/private.git', 'a' * 40, 'd' * 64),
                        previews_commitment('https://github.com/example/private.git', 'a' * 40, 'b' * 64,
                                            paths=('previews/other.yaml',))):
            self.assertNotEqual(changed, commitment)


if __name__ == '__main__':
    unittest.main()
