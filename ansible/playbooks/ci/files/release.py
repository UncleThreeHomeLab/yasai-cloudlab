"""Propose one fixture digest from a fixed GitHub-hosted receiver workflow."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def request(event, environment):
    scope = environment.get('RELEASE_SCOPE')
    actor = environment.get('RELEASE_ACTOR', '')
    repository = environment.get('GITHUB_REPOSITORY', '')
    if (scope not in ('public', 'private') or not re.fullmatch(r'[a-z0-9-]+\[bot\]', actor) or
            not re.fullmatch(r'[A-Za-z0-9-]+/[A-Za-z0-9_.-]+', repository) or
            environment.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
            environment.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or
            environment.get('GITHUB_REF') != 'refs/heads/main' or
            environment.get('GITHUB_ACTOR') != actor or
            event.get('sender', {}).get('login') != actor or event.get('sender', {}).get('type') != 'Bot' or
            event.get('repository', {}).get('full_name') != repository or
            event['repository'].get('private') is not (scope == 'private') or
            event['repository'].get('fork') is not False):
        raise ValueError('Release proposals require the fixed hosted workflow and scoped App identity')
    inputs = event.get('inputs', {})
    if (set(inputs) != {'digest', 'source_revision', 'workflow_run_id'} or
            not all(isinstance(value, str) for value in inputs.values()) or
            not re.fullmatch(r'sha256:[a-f0-9]{64}', inputs['digest']) or
            not re.fullmatch(r'[a-f0-9]{40}', inputs['source_revision']) or
            not re.fullmatch(r'[1-9][0-9]{0,19}', inputs['workflow_run_id'])):
        raise ValueError('Release proposals require an immutable digest, source revision and workflow run')
    return repository, 'apps/releases/' + scope + '-ci.json', inputs


def native(*arguments, cwd=None):
    result = subprocess.run(arguments, cwd=cwd, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError('Native release proposal failed; existing branches and PRs retained')
    return result.stdout.strip()


def propose(repository, path, desired):
    def api(suffix):
        return json.loads(native('gh', 'api', 'repos/' + repository + '/' + suffix))

    with tempfile.TemporaryDirectory(prefix='cloudlab-release-') as directory:
        directory = Path(directory)
        checkout = directory / 'source'
        git_auth = ('git', '-c', 'credential.helper=', '-c', 'credential.helper=!gh auth git-credential')
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
                   'commit', '--quiet', '-m', 'Propose fixture image ' + desired['digest'], cwd=checkout)
            native(*git_auth, 'push', '--quiet', 'origin', 'HEAD:refs/heads/' + branch, cwd=checkout)
        head = native('git', 'rev-parse', 'HEAD', cwd=checkout)
        if api('git/ref/heads/main')['object']['sha'] != base:
            raise ValueError('GitOps main advanced; regenerate the proposal without changing existing branches')
        pulls = json.loads(native('gh', 'pr', 'list', '--repo', repository, '--head', branch, '--base', 'main',
                                  '--state', 'all', '--json', 'number,state,headRefOid'))
        if len(pulls) > 1 or pulls and (pulls[0]['state'] != 'OPEN' or pulls[0]['headRefOid'] != head):
            raise ValueError('Existing release PR differs; no PR changed')
        if not pulls:
            body = directory / 'body.txt'
            body.write_text('Propose the fixture image by immutable digest. Only ' + path +
                            ' changes. Deployment remains owned by Argo; this workflow never merges.\n')
            native('gh', 'pr', 'create', '--repo', repository, '--base', 'main', '--head', branch,
                   '--title', 'Propose fixture image ' + desired['digest'][:19], '--body-file', str(body))
        return {'release_changed': True, 'pull_request_only': True}


def main():
    os.umask(0o077)
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    repository, path, desired = request(event, os.environ)
    print(json.dumps(propose(repository, path, desired)))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Release proposal incomplete; existing branches, PRs and deployments preserved') from None
