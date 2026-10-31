"""Bound private release candidates and require human promotion after verified CI."""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from playbooks.ci.files import promotion, publisher
from playbooks.ci.tests.fixtures import manual_publication, release_document


class CandidateTests(unittest.TestCase):
    def inputs(self):
        document = manual_publication()
        desired = dict(release_document(), components={'agent': release_document()['digest']}, primary_component='agent')
        return document, desired

    def test_native_oci_artifact_is_deterministic_and_exports_the_exact_bounded_metadata(self):
        document, desired = self.inputs()
        candidate = publisher.candidate_document(document, desired, '1')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            layer = directory / 'layer.tar'; layer.write_bytes(publisher.candidate_tar(candidate))
            digests = []
            for name in ('first', 'second'):
                archive = directory / (name + '.tar')
                publisher.execute(['crane', 'append', '--oci-empty-base', '--new_layer', str(layer),
                                   '--new_tag', 'candidate', '--output', str(archive)], {'PATH': os.environ['PATH']})
                digests.append(subprocess.check_output(['crane', 'digest', '--tarball', str(archive)]))
                raw = subprocess.check_output(['crane', 'export', '-', '-'], input=archive.read_bytes())
                self.assertEqual(publisher.read_candidate(raw, document, 'b' * 40, '123', '1'), desired)
            self.assertEqual(digests[0], digests[1])

    def test_metadata_cannot_change_configuration_run_components_or_add_archive_members(self):
        document, desired = self.inputs()
        candidate = publisher.candidate_document(document, desired, '1')
        for field, value in (('configuration_sha256', '0' * 64), ('workflow_run_attempt', '2'), ('extra', 'field')):
            bad = dict(candidate, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                publisher.read_candidate(publisher.candidate_tar(bad), document, 'b' * 40, '123', '1')
        for source, run, attempt in (('c' * 40, '123', '1'), ('b' * 40, '124', '1'), ('b' * 40, '123', '2')):
            with self.assertRaises(ValueError):
                publisher.read_candidate(publisher.candidate_tar(candidate), document, source, run, attempt)
        changed = dict(document, components={'worker': {'dockerfile': 'worker.Dockerfile'}}, primary_component='worker')
        with self.assertRaises(ValueError): publisher.candidate_document(changed, desired, '1')
        for kind in ('symlink', 'duplicate', 'large'):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as archive:
                info = tarfile.TarInfo('release.json')
                payload = json.dumps(candidate).encode()
                if kind == 'symlink': info.type = tarfile.SYMTYPE; info.linkname = '/outside'
                else: info.size = len(payload) if kind != 'large' else 65537
                archive.addfile(info, io.BytesIO(payload if kind != 'large' else b'x' * 65537))
                if kind == 'duplicate': archive.addfile(info, io.BytesIO(payload))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                publisher.read_candidate(stream.getvalue(), document, 'b' * 40, '123', '1')

    def test_candidate_immutable_tag_retries_and_collisions_never_overwrite(self):
        document, desired = self.inputs()
        digest = 'sha256:' + 'c' * 64
        for state in ('missing', 'matching', 'collision'):
            pushed = []
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                def execute(arguments, environment, **kwargs):
                    if arguments[1] == 'append': (directory / 'release-image.tar').write_bytes(b'bounded-artifact'); return b''
                    if arguments[1] == 'push': pushed.append(arguments[-1]); return b''
                    if kwargs.get('missing'):
                        self.assertIsInstance(kwargs['missing'], bytes)
                        diagnostic = ('GET https://registry.example.invalid/v2/cloudlab-public/example/manifests/' +
                                      arguments[-1].rsplit(':', 1)[-1] + ': NOT_FOUND').encode()
                        self.assertRegex(diagnostic, kwargs['missing'])
                        return None if state == 'missing' else ('sha256:' + ('d' if state == 'collision' else 'c') * 64).encode()
                    return digest.encode()
                with patch.object(publisher, 'execute', side_effect=execute), \
                        patch.object(publisher, 'fetch_candidate', return_value=desired), patch.object(publisher, 'sign') as sign:
                    if state == 'collision':
                        with self.assertRaises(ValueError):
                            publisher.publish_candidate(document, desired, '1', directory, {}, {}, {})
                        sign.assert_not_called()
                    else:
                        result = publisher.publish_candidate(document, desired, '1', directory, {}, {}, {})
                        self.assertEqual(result['candidate_digest'], digest)
                        self.assertFalse(result['release_proposed'])
                        sign.assert_called_once()
                self.assertEqual(len(pushed), int(state == 'missing'))

    def test_oversized_candidate_layer_is_refused_before_export(self):
        document, desired = self.inputs()
        with patch.object(publisher, 'execute', return_value=json.dumps({'schemaVersion': 2,
                'config': {'size': 100}, 'layers': [{'size': 131073}]}).encode()) as native, self.assertRaises(ValueError):
            publisher.fetch_candidate('registry.example.invalid/app@sha256:' + 'a' * 64, document,
                                      'b' * 40, '123', '1', {})
        self.assertEqual(native.call_count, 1)

    def test_manual_publisher_never_loads_or_mints_any_release_app_token(self):
        document, desired = self.inputs()
        environment = dict(PATH='/usr/bin', HOME='/tmp', RUNNER_ENVIRONMENT='self-hosted', GITHUB_REPOSITORY='example/app',
            GITHUB_REPOSITORY_ID='123', GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='push', GITHUB_SHA='b' * 40,
            GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1')
        def scan(source, directory, native, component, *, cache=None):
            archive = directory / 'image.tar'; archive.write_bytes(b'archive')
            return archive, desired['digest']
        def execute(arguments, environment, **kwargs):
            return None if kwargs.get('missing') else desired['digest'].encode()
        with patch.object(publisher, 'registry_environment', return_value={'PATH': '/usr/bin'}), \
                patch.object(publisher, 'build_and_scan', side_effect=scan), patch.object(publisher, 'execute', side_effect=execute), \
                patch.object(publisher, 'sign'), patch.object(publisher, 'publish_candidate', return_value={'candidate_published': True}) as candidate, \
                patch.object(publisher, 'credential', side_effect=AssertionError('No release credential reads')), \
                patch.object(publisher, 'release_token', side_effect=AssertionError('No App tokens')), \
                patch.object(publisher.release, 'propose', side_effect=AssertionError('No CI GitOps writes')):
            self.assertTrue(publisher.publish(document, Path('/source'), environment)['candidate_published'])
            self.assertEqual(candidate.call_args.args[1], desired)
        with patch.object(publisher, 'credential') as credential, self.assertRaises(ValueError):
            with publisher.release_token(document, {}): pass
        credential.assert_not_called()

    def test_component_named_release_and_candidate_use_distinct_immutable_tags_and_repeat_without_overwrite(self):
        document = manual_publication()
        document.update(components={'release': {'dockerfile': 'deploy/release.Dockerfile'}}, primary_component='release')
        image_digest, candidate_digest = 'sha256:' + 'a' * 64, 'sha256:' + 'c' * 64
        desired = dict(release_document(), components={'release': image_digest}, primary_component='release')
        environment = dict(PATH='/usr/bin', HOME='/tmp', RUNNER_ENVIRONMENT='self-hosted', GITHUB_REPOSITORY='example/app',
            GITHUB_REPOSITORY_ID='123', GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='push', GITHUB_SHA='b' * 40,
            GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1')
        artifacts, pushes = {}, []
        def scan(source, directory, native, component, *, cache=None):
            archive = directory / 'image.tar'; archive.write_bytes(b'scanned-runtime')
            return archive, image_digest
        def execute(arguments, native, **options):
            if arguments[0] == 'buildctl': return b''
            if arguments[1] == 'append':
                Path(arguments[-1]).write_bytes(b'bounded-candidate'); return b''
            if options.get('missing'):
                digest = artifacts.get(arguments[-1]); return digest.encode() if digest else None
            if arguments[1] == 'push':
                tag = arguments[-1]
                self.assertNotIn(tag, artifacts, 'Immutable tags must never be overwritten')
                artifacts[tag] = image_digest if Path(arguments[2]).name == 'image.tar' else candidate_digest
                pushes.append(tag); return b''
            if '--tarball' in arguments: return candidate_digest.encode()
            digest = arguments[-1].rsplit('@', 1)[-1]
            self.assertIn(digest, artifacts.values())
            return digest.encode()
        with patch.object(publisher, 'registry_environment', return_value={'PATH': '/usr/bin'}), \
                patch.object(publisher, 'build_and_scan', side_effect=scan), patch.object(publisher, 'execute', side_effect=execute), \
                patch.object(publisher, 'fetch_candidate', return_value=desired), patch.object(publisher, 'sign') as sign, \
                patch.object(publisher, 'release_token', side_effect=AssertionError('No CI GitOps token')):
            for _ in range(2):
                result = publisher.publish(document, Path('/source'), environment)
                self.assertEqual(result['candidate_digest'], candidate_digest)
            self.assertEqual(sign.call_count, 4)
        repository = 'registry.example.invalid/cloudlab-public/example'
        self.assertEqual(set(pushes), {repository + ':release-' + 'b' * 40 + '-123-1-release',
                                      repository + ':release-candidate-' + 'b' * 40 + '-123-1'})
        self.assertEqual(len(pushes), 2)


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.document = manual_publication()
        self.desired = dict(release_document(), components={'agent': release_document()['digest']}, primary_component='agent')
        raw = b'jobs:\n  test:\n    runs-on: cloudlab-example\n  publish:\n    runs-on: cloudlab-example-publish\n'
        self.pool = {'values': {'publishing': self.document, 'workflowTemplates': [{
            'job': 'publish', 'repository_id': '123', 'repository': 'example/app',
            'visibility': 'public', 'workflow_path': '.github/workflows/ci.yaml',
            'job_workflow_ref': self.document['workflow_identity'].removeprefix('https://github.com/'),
            'workflow_sha256': hashlib.sha256(raw).hexdigest()}]}}
        self.evidence = {
            'user': {'id': 1, 'type': 'User', 'login': 'human'},
            'repos/example/gitops': {'id': 456, 'full_name': 'example/gitops', 'private': True, 'fork': False,
                                     'archived': False, 'default_branch': 'main', 'permissions': {'push': True}},
            'repos/example/app': {'id': 123, 'full_name': 'example/app', 'private': False, 'fork': False,
                                  'archived': False, 'default_branch': 'main'},
            'repos/example/app/branches/main': {'protected': True},
            'repos/example/app/compare/' + 'b' * 40 + '...main': {'status': 'identical', 'base_commit': {'sha': 'b' * 40}},
            'repos/example/app/actions/runs/123/attempts/1': {'id': 123, 'run_attempt': 1, 'status': 'completed',
                'conclusion': 'success', 'head_sha': 'b' * 40, 'head_branch': 'main', 'event': 'push',
                'path': '.github/workflows/ci.yaml', 'repository': {'id': 123}, 'head_repository': {'id': 123}},
            'repos/example/app/contents/.github/workflows/ci.yaml?ref=' + 'b' * 40: {'type': 'file',
                'path': '.github/workflows/ci.yaml', 'encoding': 'base64', 'size': len(raw), 'content': base64.b64encode(raw).decode()},
            'repos/example/app/actions/runs/123/attempts/1/jobs?per_page=100': {'total_count': 2, 'jobs': [
                {'name': role, 'status': 'completed', 'conclusion': 'success', 'run_id': 123, 'head_sha': 'b' * 40,
                 'runner_name': 'local', 'labels': ['self-hosted', 'cloudlab-example' + ('-publish' if role == 'publish' else '')]}
                for role in ('test', 'publish')]}}

    def promote(self, *, signature_failure=False, candidate_failure=False):
        events = []
        def read(token, path):
            self.assertEqual(token, 'gho_synthetic_human')
            return self.evidence[path]
        def verify(reference, document, environment, source, public):
            self.assertNotIn('GH_TOKEN', environment)
            events.append('verify')
            if signature_failure and (signature_failure != 'component' or events.count('verify') == 2):
                raise ValueError('signature refused')
        def fetch(*arguments):
            events.append('candidate')
            if candidate_failure: raise ValueError('metadata refused')
            return self.desired
        def propose(repository, path, desired):
            self.assertEqual(repository, 'example/gitops'); self.assertEqual(path, 'apps/releases/example.json')
            self.assertEqual(desired, self.desired)
            self.assertEqual(os.environ['GH_TOKEN'], 'gho_synthetic_human')
            self.assertNotIn('OP_SERVICE_ACCOUNT_TOKEN', os.environ)
            self.assertEqual(events, ['verify', 'candidate', 'verify'])
            return {'release_changed': True, 'pull_request_only': True}
        def execute(arguments, environment, **kwargs):
            self.assertNotIn('GH_TOKEN', environment)
            if '@' not in arguments[-1]:
                self.assertEqual(arguments[-1], 'registry.example.invalid/cloudlab-public/example:release-candidate-' + 'b' * 40 + '-123-1')
            return ((arguments[-1].rsplit('@', 1)[-1]) if '@' in arguments[-1] else 'sha256:' + 'c' * 64).encode()
        with patch.dict(os.environ, {'PATH': os.environ['PATH'], 'HOME': '/tmp'}, clear=True), \
                patch.object(promotion, 'request', side_effect=read), \
                patch.object(promotion, 'designated_repositories', return_value=[('private-config', 'example/gitops', True)]), \
                patch.object(promotion, 'fields', return_value={'username': 'robot$cloudlab-public+pull', 'password': 'synthetic', 'secret_version': '1'}) as fields, \
                patch.object(publisher, 'execute', side_effect=execute), \
                patch.object(publisher, 'verify_signature', side_effect=verify), patch.object(publisher, 'fetch_candidate', side_effect=fetch), \
                patch.object(publisher.release, 'propose', side_effect=propose) as proposal:
            if signature_failure or candidate_failure:
                with self.assertRaises(ValueError): promotion.promote(self.pool, {}, 'gho_synthetic_human', 'sha256:' + 'c' * 64, 'b' * 40, '123', '1')
                proposal.assert_not_called()
            else:
                result = promotion.promote(self.pool, {}, 'gho_synthetic_human', 'sha256:' + 'c' * 64, 'b' * 40, '123', '1')
                fields.assert_called_once_with('harbor-cloudlab-public-pull', ('username', 'password', 'secret_version'))
                self.assertTrue(result['pull_request_only'])

    def test_only_verified_candidate_and_every_component_can_open_one_private_release_pr(self):
        self.promote()
        self.promote(signature_failure=True)
        self.promote(signature_failure='component')
        self.promote(candidate_failure=True)

    def test_nonhuman_tokens_failed_jobs_wrong_attempts_and_changed_workflows_are_refused_before_secrets(self):
        for token in ('ghs_synthetic_installation', 'github_actions_token', ''):
            with patch.object(promotion, 'request') as api, self.assertRaises(ValueError): promotion.human(token)
            api.assert_not_called()
        original = copy.deepcopy(self.evidence)
        changes = [('user', 'type', 'Bot'), ('repos/example/gitops', 'id', 999), ('repos/example/gitops', 'private', False),
            ('repos/example/app/branches/main', 'protected', False),
            ('repos/example/app/actions/runs/123/attempts/1', 'status', 'in_progress'),
            ('repos/example/app/actions/runs/123/attempts/1', 'conclusion', 'failure'),
            ('repos/example/app/actions/runs/123/attempts/1', 'run_attempt', 2),
            ('repos/example/app/actions/runs/123/attempts/1', 'head_sha', 'c' * 40),
            ('repos/example/app/actions/runs/123/attempts/1', 'head_branch', 'dev'),
            ('repos/example/app/actions/runs/123/attempts/1', 'event', 'pull_request'),
            ('repos/example/app/actions/runs/123/attempts/1/jobs?per_page=100', 'total_count', 3),
            ('repos/example/app/contents/.github/workflows/ci.yaml?ref=' + 'b' * 40, 'content', base64.b64encode(b'bad workflow').decode())]
        for path, key, value in changes:
            self.evidence = copy.deepcopy(original); self.evidence[path][key] = value
            with self.subTest(path=path, key=key), patch.object(promotion, 'request', side_effect=lambda token, path: self.evidence[path]), \
                    patch.object(promotion, 'designated_repositories', return_value=[('private-config', 'example/gitops', True)]), \
                    patch.object(promotion, 'fields') as fields, patch.object(publisher.release, 'propose') as propose, \
                    patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
                promotion.promote(self.pool, {}, 'gho_synthetic_human', 'sha256:' + 'c' * 64, 'b' * 40, '123', '1')
            fields.assert_not_called(); propose.assert_not_called()
