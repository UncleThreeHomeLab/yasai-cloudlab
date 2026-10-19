"""Qualify the published tools in disposable pods before delivering job credentials."""
import copy
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

import yaml

from playbooks.ci.files.chart import POOL, ROOT, render
from playbooks.harbor.files.transport import hostname
from playbooks.harbor.files.recovery import atomic
from playbooks.infrastructure.files import harbor as api


def images(document):
    if (not isinstance(document, dict) or set(document) != {'revision', 'images'} or
            not isinstance(document['revision'], str) or
            not re.fullmatch(r'[a-f0-9]{40}', document['revision']) or
            not isinstance(document['images'], dict) or
            set(document['images']) != {'controller', 'runner', 'builder'}):
        raise ValueError('Qualification requires the original complete bootstrap publication')
    hosts = set()
    for kind, reference in document['images'].items():
        match = re.fullmatch(r'([^/]+)/cloudlab-public/ci-' + kind + r'@sha256:[a-f0-9]{64}', reference) if isinstance(reference, str) else None
        if not match:
            raise ValueError('Qualification accepts only the three published public tool digests')
        hosts.add(hostname(match[1]))
    if len(hosts) != 1:
        raise ValueError('Qualification cannot mix registry installations')
    return document['images']


def bundle(references, namespace):
    if not re.fullmatch(r'cloudlab-ci-proof-[a-f0-9]{12}', namespace):
        raise ValueError('Qualification must use a fresh disposable namespace')
    labels = {'cloudlab.io/fixture': 'ci-bootstrap', 'cloudlab.io/owner': 'ci-platform'}
    controller_repository, controller_digest = references['controller'].split('@')
    rendered = render({'arc': {'image': {'repository': controller_repository,
                                        'tag': '0.15.0@' + controller_digest}}})
    pull = next(row for row in rendered if row['kind'] == 'ExternalSecret')
    pull['metadata'] = {'name': 'harbor-tools-pull', 'namespace': namespace, 'labels': labels}
    permissions = list(yaml.safe_load_all((POOL / 'templates/health.yaml').read_text()))
    account, role, binding = permissions
    account['metadata'] = {'name': 'health', 'namespace': namespace, 'labels': labels}
    role['metadata'] = {'name': namespace, 'labels': labels}
    binding['metadata'] = {'name': namespace, 'labels': labels}
    binding['roleRef']['name'] = namespace
    binding['subjects'] = [{'kind': 'ServiceAccount', 'name': 'health', 'namespace': namespace}]
    ids = yaml.safe_load((POOL / 'templates/builder-ids.yaml').read_text())
    ids['metadata'].update(namespace=namespace, labels=labels)
    policy = {'apiVersion': 'v1', 'kind': 'ConfigMap',
              'metadata': {'name': 'cloudlab-ci-eligibility', 'namespace': namespace, 'labels': labels},
              'data': {'eligibility.json': '{"workflows":[]}'}}
    proof = {'apiVersion': 'v1', 'kind': 'ConfigMap',
             'metadata': {'name': 'proof', 'namespace': namespace, 'labels': labels}, 'data': {
                 'build-proof.sh': (ROOT / 'ansible/playbooks/buildkit/files/build-proof.sh').read_text(),
                 'api-denial.py': (Path(__file__).parent / 'api-denial.py').read_text()}}
    quota = {'apiVersion': 'v1', 'kind': 'ResourceQuota',
             'metadata': {'name': 'build-budget', 'namespace': namespace, 'labels': labels}, 'spec': {'hard': {
                 'pods': '1', 'count/jobs.batch': '1', 'limits.cpu': '3', 'limits.memory': '6Gi',
                 'limits.ephemeral-storage': '32Gi', 'persistentvolumeclaims': '0', 'secrets': '1'}}}
    pod = copy.deepcopy(json.loads((POOL / 'values.json').read_text())['arc']['template']['spec'])
    pod['serviceAccountName'] = 'health'
    runner, = pod['containers']
    builder, = pod['initContainers']
    runner['image'], builder['image'] = references['runner'], references['builder']
    runner['args'] = ["python3 -I -S /usr/local/libexec/cloudlab-ci-health.py\n"
                      "trap 'exit 143' TERM INT\nwhile true; do sleep 1 & wait $!; done"]
    runner['env'].append({'name': 'POD_NAMESPACE', 'value': namespace})
    builder['env'].append({'name': 'BUILD_PROOF_WORKSPACE', 'value': '/tmp/ci-proof'})
    for container in (runner, builder):
        container['volumeMounts'].append({'name': 'proof', 'mountPath': '/proof', 'readOnly': True})
    pod['volumes'].append({'name': 'proof', 'configMap': {'name': 'proof', 'defaultMode': 292}})
    return {'namespace': {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {
                'name': namespace, 'labels': dict(labels, **{
                    'cloudlab.io/service-secrets': 'approved',
                    'pod-security.kubernetes.io/enforce': 'baseline',
                    'pod-security.kubernetes.io/enforce-version': 'v1.36',
                    'pod-security.kubernetes.io/audit': 'restricted',
                    'pod-security.kubernetes.io/audit-version': 'v1.36',
                    'pod-security.kubernetes.io/warn': 'restricted',
                    'pod-security.kubernetes.io/warn-version': 'v1.36'})}},
            'resources': {'apiVersion': 'v1', 'kind': 'List', 'items': [quota, account, role, ids, policy, proof, pull]},
            'binding': binding, 'pod': pod}


def ansible_inputs(configuration):
    # Decode only at the final module argument; Ansible must not parse ESO's Go templates.
    return {**{key: value for key, value in configuration.items() if key != 'resources'},
            'resources_b64': base64.b64encode(json.dumps(configuration['resources']).encode()).decode()}


def main():
    os.umask(0o077)
    with (api.WORK / 'client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        revision = api.binding()
        document = json.loads((api.WORK / 'ci/images.json').read_text())
        references = images(document)
        repository = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']
        environment = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
        if not api.reviewed_ancestor(repository, document['revision'], revision, environment):
            raise ValueError('Bootstrap images must originate from a reviewed ancestor')
        configuration = bundle(references, 'cloudlab-ci-proof-' + secrets.token_hex(6))
        result = subprocess.run(['ansible-playbook', '-i', 'inventory.yml', 'playbooks/ci/verify-bootstrap.yml',
                                 '--extra-vars', '@/dev/stdin'], input=json.dumps({'ci_fixture': ansible_inputs(configuration)}),
                                text=True, cwd=ROOT / 'ansible', check=False)
        if result.returncode == 0:
            profile = hashlib.sha256(b''.join(path.read_bytes() for path in (
                POOL / 'values.json', POOL / 'templates/health.yaml', POOL / 'templates/builder-ids.yaml',
                ROOT / 'ansible/playbooks/buildkit/files/buildkit-seccomp.json',
                ROOT / 'ansible/playbooks/buildkit/files/cloudlab-buildkit'))).hexdigest()
            atomic(api.WORK / 'ci/qualified.json', {
                'revision': revision, 'image_revision': document['revision'], 'images': references,
                'profile_sha256': profile, 'nodes_verified': 2, 'max_build_pods': 1,
                'health_access_loss_shutdown_bound_seconds': 90, 'workload_api_writes_denied': True,
                'github_or_signing_credentials_provisioned': False})
        raise SystemExit(result.returncode)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('CI qualification incomplete; no job credentials provisioned') from None
