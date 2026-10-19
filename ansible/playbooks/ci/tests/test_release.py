"""Exercise receiver trust checks and real local Git interruption/repeat behavior."""
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import urllib.parse
from unittest.mock import patch

from playbooks.ci.files import release
from playbooks.ci.tests.fixtures import release_request


class ReleaseRequestTests(unittest.TestCase):
    def test_api_authentication_is_in_headers_and_redirects_are_disabled(self):
        class Response(io.BytesIO):
            status = 200
        from unittest.mock import Mock
        opener = Mock()
        opener.open.return_value = Response(b'{"number":1}')
        with patch.object(release.urllib.request, 'build_opener', return_value=opener) as build:
            self.assertEqual(release.api('POST', 'repos/example/gitops/pulls', {'head': 'release/reviewed'},
                                         token='synthetic-token'), {'number': 1})
        self.assertIsInstance(build.call_args.args[0], release.NoRedirect)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header('Authorization'), 'Bearer synthetic-token')
        self.assertNotIn('synthetic-token', request.full_url)
        self.assertNotIn(b'synthetic-token', request.data)
        self.assertIsNone(release.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.invalid'))
        with patch.object(release.urllib.request, 'build_opener') as build:
            with self.assertRaises(ValueError):
                release.api('GET', 'repos/example/gitops', token='invalid\nvalue')
            build.assert_not_called()

    def test_exact_local_main_and_bot_identity_is_required_before_any_native_command(self):
        event, environment = release_request()
        self.assertEqual(release.request(event, environment),
                         ('example/gitops', 'apps/releases/private-ci.json', event['inputs']))
        for key, value in (('RUNNER_ENVIRONMENT', 'github-hosted'), ('GITHUB_REF', 'refs/heads/unreviewed'),
                           ('GITHUB_EVENT_NAME', 'pull_request_target'), ('GITHUB_ACTOR', 'other[bot]'),
                           ('RELEASE_SCOPE', '../identity'), ('GITHUB_REPOSITORY', '--exec=bad')):
            with self.subTest(key=key), patch.object(release, 'native') as native:
                with self.assertRaises(ValueError):
                    release.request(event, dict(environment, **{key: value}))
                native.assert_not_called()
        for location, field, value in (('sender', 'type', 'User'), ('sender', 'login', 'other[bot]'),
                                       ('repository', 'private', False), ('repository', 'fork', True),
                                       ('repository', 'full_name', 'example/other')):
            changed = copy.deepcopy(event)
            changed[location][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                release.request(changed, environment)

    def test_dispatch_inputs_cannot_choose_paths_commands_or_mutable_artifacts(self):
        event, environment = release_request()
        for key, value in (('digest', 'latest'), ('digest', 'sha256:' + 'a' * 64 + '\n'),
                           ('source_revision', 'main'), ('workflow_run_id', '$(command)'),
                           ('workflow_run_id', 123), ('path', 'identity/configmap.yaml')):
            changed = copy.deepcopy(event)
            changed['inputs'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                release.request(changed, environment)


class ReleaseGitTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.remote = self.root / 'remote.git'
        self.seed = self.root / 'seed'
        self.original = release.native
        self.original('git', 'init', '--quiet', '--bare', '--initial-branch=main', str(self.remote))
        self.original('git', 'init', '--quiet', '--initial-branch=main', str(self.seed))
        self.environment = patch.dict(os.environ, {
            'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_SYSTEM': os.devnull, 'GIT_TERMINAL_PROMPT': '0',
            'GIT_CONFIG_COUNT': '3',
            'GIT_CONFIG_KEY_0': 'url.' + self.remote.as_uri() + '.insteadOf',
            'GIT_CONFIG_VALUE_0': 'https://github.com/example/gitops.git',
            'GIT_CONFIG_KEY_1': 'user.name', 'GIT_CONFIG_VALUE_1': 'Fixture',
            'GIT_CONFIG_KEY_2': 'user.email', 'GIT_CONFIG_VALUE_2': 'fixture@example.invalid'})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        (self.seed / 'retained.txt').write_bytes(b'preserve unrelated data')
        self.original('git', 'add', '.', cwd=self.seed)
        self.original('git', 'commit', '--quiet', '-m', 'Retained baseline', cwd=self.seed)
        self.original('git', 'push', '--quiet', str(self.remote), 'HEAD:refs/heads/main', cwd=self.seed)
        self.base = self.ref('main')
        event, _ = release_request()
        self.desired = event['inputs']
        self.path = 'apps/releases/private-ci.json'
        self.pulls = []
        self.pr_creations = 0
        self.interruption = None

    def ref(self, branch):
        return self.original('git', '--git-dir=' + str(self.remote), 'rev-parse', 'refs/heads/' + branch)

    def api(self, method, path, document=None):
        if path == 'repos/example/gitops/git/ref/heads/main':
            self.assertEqual(method, 'GET')
            return {'object': {'sha': self.ref('main')}}
        if path.startswith('repos/example/gitops/pulls?'):
            self.assertEqual(method, 'GET')
            branch = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['head'][0].split(':', 1)[1]
            return [{'number': row['number'], 'state': row['state'].lower(), 'head': {'sha': row['headRefOid']}}
                    for row in self.pulls if row['headRefName'] == branch]
        if path == 'repos/example/gitops/pulls' and method == 'POST':
            branch = document['head']
            self.pulls.append({'number': len(self.pulls) + 1, 'state': 'OPEN',
                               'headRefOid': self.ref(branch), 'headRefName': branch})
            self.pr_creations += 1
            if self.interruption == 'pr':
                self.interruption = None
                raise RuntimeError('Lost PR creation response')
            return {'number': 1}
        raise AssertionError('Unexpected release API request')

    def execute(self, *arguments, cwd=None):
        self.assertEqual(arguments[0], 'git')
        self.assertNotIn('--force', arguments)
        result = self.original(*arguments, cwd=cwd)
        if 'push' in arguments and self.interruption == 'push':
            self.interruption = None
            raise RuntimeError('Lost successful push response')
        return result

    def propose(self):
        with patch.object(release, 'native', side_effect=self.execute), patch.object(release, 'api', side_effect=self.api):
            return release.propose('example/gitops', self.path, self.desired)

    def branches(self):
        return self.original('git', '--git-dir=' + str(self.remote), 'for-each-ref',
                             '--format=%(refname:short)', 'refs/heads/release').splitlines()

    def test_real_git_repeat_creates_one_bounded_pr_and_never_merges(self):
        self.assertEqual(self.propose(), {'release_changed': True, 'pull_request_only': True})
        branch, = self.branches()
        head = self.ref(branch)
        self.assertEqual(self.original('git', '--git-dir=' + str(self.remote), 'diff', '--name-only',
                                       self.base, head), self.path)
        self.assertEqual(json.loads(self.original('git', '--git-dir=' + str(self.remote), 'show',
                                                  head + ':' + self.path)), self.desired)
        self.propose()
        self.assertEqual(self.ref(branch), head)
        self.assertEqual(self.ref('main'), self.base)
        self.assertEqual(self.pr_creations, 1)
        self.original('git', '--git-dir=' + str(self.remote), 'update-ref', 'refs/heads/main', head, self.base)
        self.assertEqual(self.propose(), {'release_changed': False})
        self.assertEqual(self.pr_creations, 1)

    def test_lost_push_or_pr_response_preserves_branch_and_resumes_without_overwrite(self):
        for interruption in ('push', 'pr'):
            self.interruption = interruption
            self.desired = dict(self.desired, workflow_run_id=str(123 + len(self.pulls)))
            with self.assertRaises(RuntimeError):
                self.propose()
            heads = {branch: self.ref(branch) for branch in self.branches()}
            self.propose()
            self.assertEqual({branch: self.ref(branch) for branch in self.branches()}, heads)
            self.assertEqual(self.ref('main'), self.base)

    def test_independently_changed_branch_or_closed_pr_is_retained_and_refused(self):
        self.propose()
        branch, = self.branches()
        self.pulls[0]['state'] = 'CLOSED'
        with self.assertRaises(ValueError):
            self.propose()
        self.assertEqual(self.pr_creations, 1)
        self.original('git', 'fetch', '--quiet', str(self.remote), 'refs/heads/' + branch, cwd=self.seed)
        self.original('git', 'checkout', '--quiet', '--detach', 'FETCH_HEAD', cwd=self.seed)
        (self.seed / 'foreign.txt').write_bytes(b'preserve foreign change')
        self.original('git', 'add', '.', cwd=self.seed)
        self.original('git', 'commit', '--quiet', '-m', 'Foreign change', cwd=self.seed)
        self.original('git', 'push', '--quiet', str(self.remote), 'HEAD:refs/heads/' + branch, cwd=self.seed)
        foreign = self.ref(branch)
        with self.assertRaises(ValueError):
            self.propose()
        self.assertEqual(self.ref(branch), foreign)
        self.assertEqual(self.ref('main'), self.base)

    def test_main_advance_preserves_pushed_branch_without_creating_a_pr(self):
        def advanced(*arguments, cwd=None):
            if arguments[:2] == ('gh', 'api'):
                return json.dumps({'object': {'sha': 'c' * 40}})
            return self.execute(*arguments, cwd=cwd)
        with patch.object(release, 'native', side_effect=advanced), self.assertRaises(ValueError):
            release.propose('example/gitops', self.path, self.desired)
        branch, = self.branches()
        head = self.ref(branch)
        self.assertEqual(self.pr_creations, 0)
        self.propose()
        self.assertEqual(self.ref(branch), head)
        self.assertEqual(self.pr_creations, 1)

    def test_symlinked_destination_is_refused_before_reading_or_writing_outside_checkout(self):
        outside = self.root / 'outside'
        (outside / 'releases').mkdir(parents=True)
        target = outside / 'releases/private-ci.json'
        target.write_text(json.dumps(self.desired))
        (self.seed / 'apps').symlink_to(outside, target_is_directory=True)
        self.original('git', 'add', 'apps', cwd=self.seed)
        self.original('git', 'commit', '--quiet', '-m', 'Retained symlink', cwd=self.seed)
        self.original('git', 'push', '--quiet', str(self.remote), 'HEAD:refs/heads/main', cwd=self.seed)
        self.base = self.ref('main')
        before = target.read_bytes()
        with self.assertRaisesRegex(ValueError, 'symlinks'):
            self.propose()
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(self.branches(), [])
        self.assertEqual(self.pr_creations, 0)
