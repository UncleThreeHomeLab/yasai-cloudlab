"""Publish only a reviewed current tree, without importing private Git history."""
import base64
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile

from github_setup import ROOT, configuration, inputs, inspect

FORBIDDEN = {'platform-plan.md', 'automation-migration-plan.md', 'milestone-prompts.md',
             'platform-decisions.md', 'platform-inputs.md', 'platform-compatibility.md'}


def git(directory, *args, env=None, data=None, allow_failure=False):
    result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(directory), *args],
        input=data, capture_output=True, timeout=180, env=env)
    if result.returncode and not allow_failure:
        raise RuntimeError('Snapshot Git operation failed; private diagnostics withheld')
    return result


def validate_file(name, data, values):
    path = PurePosixPath(name)
    if (path.is_absolute() or '..' in path.parts or '.git' in path.parts or
            path.name in FORBIDDEN or name.startswith('docs/assets/design-sections/') or
            path.name.startswith('platform-design.') or
            (path.name.startswith('.env') and path.name != '.env.example') or
            path.suffix in ('.pem', '.key', '.kubeconfig') or path.name in ('id_rsa', 'id_ed25519')):
        raise RuntimeError('Snapshot contains a forbidden private file')
    for key, value in values.items():
        if value and (len(value) >= 12 or (key.endswith('_HOST') and len(value) > 5)):
            if value.encode() in data:
                raise RuntimeError('Snapshot contains a bootstrap or private input value')
    if re.search(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----\s+[A-Za-z0-9+/=]{40}', data):
        raise RuntimeError('Snapshot contains a private key payload')


def snapshot(values):
    if git(ROOT, 'status', '--porcelain').stdout.strip():
        raise RuntimeError('Snapshot publication requires a clean reviewed checkout')
    archive = git(ROOT, 'archive', '--format=tar', 'HEAD').stdout
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar:
            if member.isdir():
                continue
            if not member.isfile():
                raise RuntimeError('Snapshot cannot publish symlinks or special files')
            data = tar.extractfile(member).read()
            validate_file(member.name, data, values)
            if member.name.endswith('.tgz'):
                with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as nested:
                    for child in nested:
                        if child.isfile():
                            validate_file(child.name, nested.extractfile(child).read(), values)
            files[member.name] = (data, member.mode)
    return files


def publish(api, values):
    role, repo, private = configuration(values)[0]
    if inspect(api, role, repo, private) is None:
        raise RuntimeError('Provision the declared public repository before publishing')
    files = snapshot(values)
    authorization = base64.b64encode(('x-access-token:' + api.token).encode()).decode()
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0',
        GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.https://github.com/.extraheader',
        GIT_CONFIG_VALUE_0='AUTHORIZATION: basic ' + authorization,
        GIT_AUTHOR_NAME='CloudLab Automation', GIT_COMMITTER_NAME='CloudLab Automation',
        GIT_AUTHOR_EMAIL='noreply@users.noreply.github.com', GIT_COMMITTER_EMAIL='noreply@users.noreply.github.com')
    url = 'https://github.com/' + repo + '.git'
    with tempfile.TemporaryDirectory(prefix='cloudlab-publication-') as folder:
        target = Path(folder)
        git(target, 'init', '--initial-branch=main', '--template=', env=env)
        refs = git(target, 'ls-remote', '--heads', '--tags', url, env=env).stdout.decode().splitlines()
        if refs and (len(refs) != 1 or not refs[0].endswith('\trefs/heads/main')):
            raise RuntimeError('Initial snapshot publisher refuses unexpected branches or tags')
        if refs:
            git(target, 'fetch', '--no-tags', url, 'refs/heads/main', env=env)
            git(target, 'reset', '--soft', 'FETCH_HEAD', env=env)
        git(target, 'read-tree', '--empty', env=env)
        for name, (data, mode) in files.items():
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode & 0o777)
        git(target, 'add', '--all', env=env)
        tree = git(target, 'write-tree', env=env).stdout.strip()
        if refs and tree == git(target, 'rev-parse', 'HEAD^{tree}', env=env).stdout.strip():
            return {'published': False, 'tree_unchanged': True, 'files_scanned': len(files)}
        if refs:
            raise RuntimeError('Public source is already initialized; make changes in its canonical checkout')
        # Publication is a one-time boundary, not a second writer for public Git.
        git(target, 'commit', '-m', 'Publish reviewed CloudLab platform snapshot', env=env)
        git(target, 'push', url, 'HEAD:refs/heads/main', env=env)
        revision = git(target, 'rev-parse', 'HEAD', env=env).stdout.decode().strip()
        return {'published': True, 'files_scanned': len(files), 'public_revision': revision}


if __name__ == '__main__':
    try:
        values, api = inputs()
        print(json.dumps(publish(api, values)))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else 'Snapshot publication failed; private diagnostics withheld') from None
