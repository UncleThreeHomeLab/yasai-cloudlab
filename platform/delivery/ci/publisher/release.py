"""Propose one application digest in its single approved GitOps release file."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request


class ReleaseFailure(RuntimeError):
    """Fixed failure categories; never include private command or HTTP output."""


def native(*arguments, cwd=None):
    result = subprocess.run(arguments, cwd=cwd, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise ReleaseFailure('Native release Git operation failed (exit ' + str(result.returncode) +
                             '); existing branches and PRs retained')
    return result.stdout.strip()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api(method, path, document=None, *, token=None):
    token = os.environ.get('GH_TOKEN', '') if token is None else token
    if not isinstance(token, str) or not token or any(character.isspace() for character in token):
        raise ValueError('Release API requires its scoped token')
    request = urllib.request.Request('https://api.github.com/' + path, method=method,
        data=json.dumps(document).encode() if document is not None else None,
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                 'Content-Type': 'application/json', 'User-Agent': 'cloudlab-release/1',
                 'X-GitHub-Api-Version': '2022-11-28'})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            if response.status == 204:
                return None
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError('Release response exceeds its bound')
        return json.loads(raw)
    except urllib.error.HTTPError as error:
        raise ReleaseFailure('Release API ' + method + ' failed (HTTP ' + str(error.code) +
                             '); existing branches and PRs retained') from None
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise ReleaseFailure('Release API unavailable; existing branches and PRs retained') from None


def validate(desired):
    base_fields = {'digest', 'source_revision', 'workflow_run_id'}
    if (set(desired) not in (base_fields, base_fields | {'components', 'primary_component'}) or
            not all(isinstance(desired.get(key), str) for key in base_fields) or
            not re.fullmatch(r'sha256:[a-f0-9]{64}', desired['digest']) or
            not re.fullmatch(r'[a-f0-9]{40}', desired['source_revision']) or
            not re.fullmatch(r'[1-9][0-9]{0,19}', desired['workflow_run_id'])):
        raise ValueError('Release proposals require an immutable digest, source revision and workflow run')
    if 'components' in desired:
        components, primary = desired['components'], desired['primary_component']
        if (not isinstance(components, dict) or not 1 <= len(components) <= 8 or
                not isinstance(primary, str) or primary not in components or components[primary] != desired['digest'] or
                any(not isinstance(name, str) or not re.fullmatch(r'[a-z](?:[a-z0-9-]{0,33}[a-z0-9])?', name) or
                    not isinstance(digest, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest)
                    for name, digest in components.items())):
            raise ValueError('Component releases require bounded named digests matching their explicit primary')
    return desired


def canonical(desired):
    """Canonical record bytes; reviewer submissions must match the proposer byte for byte."""
    return (json.dumps(validate(desired), sort_keys=True, indent=2) + '\n').encode()


def verify(registration, desired, application):
    """Trusted offline validation of a reviewer-submitted release record.

    Holds no GitOps write credential: it joins the submitted record against
    the approved private registration (exact-revision binding, approved
    components and primary). Run it as the merge gate on the release PR; a
    gate failure blocks the PR. Anything merged invalid is still denied at
    admission, and Argo keeps serving the prior merged release.
    """
    validate(desired)
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,34}', application):
        raise ValueError('Release verification requires its approved application name')
    if not isinstance(registration, dict) or registration.get('application') != application:
        raise ValueError('Release verification requires its approved application registration')
    approval = registration.get('ci', {}).get('approval', {}) if isinstance(
        registration.get('ci'), dict) else {}
    if (not isinstance(approval, dict) or
            not re.fullmatch(r'[a-f0-9]{40}', approval.get('revision', '')) or
            desired['source_revision'] != approval['revision']):
        raise ValueError('Release source revision lacks its exact approved registration revision')
    publishing = registration.get('publishing', {})
    if not isinstance(publishing, dict):
        raise ValueError('Release verification requires its approved publishing registration')
    components = publishing.get('components')
    if components is None:
        if 'components' in desired or 'primary_component' in desired:
            raise ValueError('Release components lack their approved registration components')
    elif (not isinstance(components, dict) or
            set(desired.get('components', {})) != set(components) or
            desired.get('primary_component') != publishing.get('primaryComponent')):
        raise ValueError('Release components differ from their approved registration')
    return desired


def propose(repository, path, desired):
    if (not re.fullmatch(r'[A-Za-z0-9-]+/[A-Za-z0-9_.-]+', repository) or
            not re.fullmatch(r'apps/releases/[a-z][a-z0-9-]{0,34}[.]json', path)):
        raise ValueError('Release proposal requires its approved repository and artifact file')
    validate(desired)
    prefix = 'repos/' + repository

    with tempfile.TemporaryDirectory(prefix='cloudlab-release-') as directory:
        directory = Path(directory)
        checkout = directory / 'source'
        # Git reads the token through its credential protocol, never through argv or persistent config.
        helper = '!f() { printf "%s\\n" "username=x-access-token" "password=$GH_TOKEN"; }; f'
        git_auth = ('git', '-c', 'credential.helper=', '-c', 'credential.helper=' + helper)
        native(*git_auth, 'clone', '--quiet', '--depth=1', '--branch', 'main', '--single-branch',
               'https://github.com/' + repository + '.git', str(checkout))
        base = native('git', 'rev-parse', 'HEAD', cwd=checkout)
        target = checkout / path
        if any(parent.is_symlink() for parent in (target, *target.parents)):
            raise ValueError('Release destination cannot follow symlinks')
        if target.is_file() and json.loads(target.read_text()) == desired:
            return {'release_changed': False}
        content = json.dumps(desired, sort_keys=True, indent=2) + '\n'
        branch = 'release/' + hashlib.sha256((base + path + content).encode()).hexdigest()[:24]
        remote = native(*git_auth, 'ls-remote', '--heads', 'origin', 'refs/heads/' + branch, cwd=checkout)
        if remote:
            native(*git_auth, 'fetch', '--quiet', '--depth=2', 'origin', 'refs/heads/' + branch, cwd=checkout)
            native('git', 'checkout', '--quiet', '--detach', 'FETCH_HEAD', cwd=checkout)
            if (native('git', 'rev-list', '--count', base + '..HEAD', cwd=checkout) != '1' or
                    native('git', 'rev-parse', 'HEAD^', cwd=checkout) != base or
                    native('git', 'diff', '--name-only', base, 'HEAD', cwd=checkout) != path or
                    not target.is_file() or target.is_symlink() or target.read_text() != content):
                raise ValueError('Existing release branch differs; overwrite refused')
        else:
            native('git', 'switch', '--quiet', '-c', branch, cwd=checkout)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
            native('git', 'add', '--', path, cwd=checkout)
            if native('git', 'diff', '--cached', '--name-only', cwd=checkout) != path:
                raise ValueError('Release proposal exceeds its single approved file')
            native('git', '-c', 'user.name=CloudLab releases', '-c', 'user.email=releases@example.invalid',
                   'commit', '--quiet', '-m', 'Propose image ' + desired['digest'], cwd=checkout)
            native(*git_auth, 'push', '--quiet', 'origin', 'HEAD:refs/heads/' + branch, cwd=checkout)
        head = native('git', 'rev-parse', 'HEAD', cwd=checkout)
        if api('GET', prefix + '/git/ref/heads/main')['object']['sha'] != base:
            raise ValueError('GitOps main advanced; regenerate the proposal without changing existing branches')
        query = urllib.parse.urlencode({'head': repository.split('/')[0] + ':' + branch,
                                        'base': 'main', 'state': 'all', 'per_page': 100})
        pulls = api('GET', prefix + '/pulls?' + query)
        if len(pulls) > 1 or pulls and (pulls[0]['state'] != 'open' or pulls[0]['head']['sha'] != head):
            raise ValueError('Existing release PR differs; no PR changed')
        if not pulls:
            api('POST', prefix + '/pulls', {'base': 'main', 'head': branch,
                'title': 'Propose image ' + desired['digest'][:19],
                'body': 'Propose the image by immutable digest. Only ' + path +
                        ' changes. Deployment remains owned by Argo; this workflow never merges.\n'})
        return {'release_changed': True, 'pull_request_only': True}


def main(arguments):
    if len(arguments) != 3 or arguments[0] != 'verify':
        raise SystemExit('Release verification requires: release.py verify <registration.json> <release-file>')
    registration_raw = Path(arguments[1]).read_bytes()
    release_raw = Path(arguments[2]).read_bytes()
    if len(registration_raw) > 65536 or len(release_raw) > 65536:
        raise SystemExit('Release verification input exceeds its bound')
    match = re.fullmatch(r'(?:.*/)?apps/releases/([a-z][a-z0-9-]{0,34})[.]json',
                         arguments[2].replace('\\', '/'))
    if match is None:
        raise SystemExit('Release verification requires its approved artifact file')
    try:
        registration, desired = json.loads(registration_raw), json.loads(release_raw)
    except ValueError:
        raise SystemExit('Release verification requires valid JSON documents') from None
    try:
        verify(registration, desired, match[1])
    except ValueError as error:
        raise SystemExit(str(error)) from None
    if release_raw != canonical(desired):
        raise SystemExit('Release submission must match the canonical record bytes')
    print(json.dumps({'verified': True, 'application': match[1]}))


if __name__ == '__main__':
    try:
        main(sys.argv[1:] if len(sys.argv) > 1 else [])
    except SystemExit:
        raise
    except OSError:
        raise SystemExit('Release verification input unavailable') from None
