"""Render the same locked charts used by bootstrap and Argo CD."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import yaml

ROOT = Path(__file__).resolve().parents[2]
OPERATOR = ROOT / 'platform/delivery/argocd'
PUBLIC = ROOT / 'gitops/roots/public'


def documents(path, release, version):
    result = subprocess.run(['helm', 'template', release, str(path), '--namespace', 'argocd',
        '--kube-version', version, '--include-crds'], capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError('Locked GitOps chart render failed')
    return [x for x in yaml.safe_load_all(result.stdout) if x]


def images(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == 'image' and isinstance(child, str):
                yield child
            else:
                yield from images(child)
    elif isinstance(value, list):
        for child in value:
            yield from images(child)


def payload():
    lock = json.loads((OPERATOR / 'artifact.lock.json').read_text())
    archive = OPERATOR / lock['chart']['archive']
    if hashlib.sha256(archive.read_bytes()).hexdigest() != lock['chart']['sha256']:
        raise RuntimeError('Argo chart checksum mismatch')
    version = subprocess.check_output(['helm', 'version', '--short'], text=True).strip()
    if not version.startswith('v' + lock['helm_version'] + '+'):
        raise RuntimeError('GitOps render requires the locked Helm tool')
    operator = documents(OPERATOR, 'argocd', lock['kube_version'])
    if operator != documents(OPERATOR, 'argocd', lock['kube_version']):
        raise RuntimeError('Argo chart render is nondeterministic')
    expected = {name + '@' + digest for name, digest in lock['images'].items()}
    if set(images(operator)) != expected:
        raise RuntimeError('Argo chart image references differ from the lock')
    if any(x['kind'] == 'Service' and x.get('spec', {}).get('type', 'ClusterIP') != 'ClusterIP' for x in operator):
        raise RuntimeError('Argo services must remain private ClusterIP services')
    roots = documents(PUBLIC, 'cloudlab-public-root', lock['kube_version'])
    for obj in roots:
        if obj['kind'] == 'Application':
            options = obj['spec']['syncPolicy']['syncOptions']
            if any(x in options for x in ('ServerSideApply=true', 'Replace=true', 'Force=true')):
                raise RuntimeError('Broad forced ownership or replacement is forbidden')
    source = yaml.safe_load((PUBLIC / 'values.yaml').read_text())
    probe_image = next(image for image in expected if image.startswith('quay.io/argoproj/argocd:'))
    return {'operator': operator, 'roots': roots, 'version': lock['chart']['app_version'],
            'repository': source['repository'], 'branch': source['revision'],
            'public_namespace': source['publicNamespace'], 'probe_image': probe_image,
            'image_refs': sorted(expected)}


def committed_payload():
    data = payload()
    paths = ['platform/delivery/argocd', 'gitops', 'automation/gitops', 'ansible/roles/gitops',
             'platform/secrets/external-secrets', 'automation/external_secrets',
             'ansible/roles/external_secrets', 'ansible/group_vars/all/secrets.yml',
             'platform/storage/longhorn', 'automation/longhorn', 'ansible/roles/longhorn',
             'ansible/group_vars/all/storage.yml', 'platform/storage/longhorn-backup',
             'ansible/roles/longhorn_backup', 'platform/certificates', 'automation/certificates',
             'ansible/roles/certificates', 'ansible/group_vars/all/certificates.yml',
               'platform/connectivity', 'automation/connectivity', 'ansible/roles/connectivity',
               'ansible/group_vars/all/connectivity.yml', 'ansible/access.yml', 'ansible/access-cutover.yml',
               'ansible/roles/k3s',
               'automation/mesh', 'ansible/roles/mesh', 'ansible/group_vars/all/mesh.yml']
    result = subprocess.run(['git', '-C', str(ROOT), 'status', '--porcelain', '--', *paths],
                            capture_output=True, text=True, timeout=30, check=True)
    if result.stdout.strip():
        raise RuntimeError('Commit the reviewed GitOps inputs before live bootstrap')
    data['revision'] = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    data['stop_after_seed'] = os.environ.get('LAB_GITOPS_STOP_AFTER_SEED') == '1'
    source = yaml.safe_load((PUBLIC / 'values.yaml').read_text())
    if (not re.fullmatch(r'https://github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+[.]git', source['repository']) or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9/_-]*', source['revision'])):
        raise RuntimeError('Public root requires an explicit GitHub HTTPS repository and branch')
    remote = subprocess.run(['git', '-c', 'credential.helper=', 'ls-remote', '--exit-code',
        source['repository'], 'refs/heads/' + source['revision']], capture_output=True, text=True,
        timeout=60, env=dict(os.environ, GIT_TERMINAL_PROMPT='0'))
    if remote.returncode or not remote.stdout.split():
        raise RuntimeError('Public GitOps source is not anonymously readable; verify repository visibility and network access')
    if remote.stdout.split()[0] != data['revision']:
        raise RuntimeError('Publish the reviewed commit before public GitOps bootstrap')
    return data


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['check']:
            data = payload()
            print(json.dumps({'operator_objects': len(data['operator']), 'root_objects': len(data['roots']),
                              'images': len(set(images(data['operator']))), 'deterministic': True}))
        elif sys.argv[1:] == ['preflight']:
            committed_payload()
            print('Public GitOps source and committed inputs verified.')
        else:
            print(json.dumps(committed_payload()))
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
    except (ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit('GitOps rendering or artifact validation failed') from None
