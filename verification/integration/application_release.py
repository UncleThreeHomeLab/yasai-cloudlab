"""Prove approved application signatures, isolation and node pulls without deploying test code."""
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sys
import tempfile
import traceback


def isolated_policy(policy, pod_name, nonce):
    result = {'apiVersion': policy['apiVersion'], 'kind': 'Policy', 'metadata': {
        'name': 'artifact-release-proof', 'namespace': policy['metadata']['namespace'],
        'labels': {'cloudlab.io/owner': 'application-release-proof', 'cloudlab.io/fixture': nonce},
        'annotations': {'pod-policies.kyverno.io/autogen-controllers': 'none'}},
        'spec': copy.deepcopy(policy['spec'])}
    result['spec']['validationFailureAction'] = 'Enforce'
    for rule in result['spec']['rules']:
        for match in rule['match']['any']:
            match['resources']['names'] = [pod_name]
            match['resources']['selector'] = {'matchLabels': {'cloudlab.io/release-proof': nonce}}
    return result


def public_pool(approval):
    from playbooks.istio.files.kube import get, kube
    pool_namespace = 'cloudlab-ci-public-' + approval['name']
    sets = (get('autoscalingrunnersets.actions.github.com', namespace=pool_namespace) or {}).get('items', [])
    quota = get('resourcequota', 'runner-budget', pool_namespace)
    allowed = {'github-arc-public', 'harbor-cloudlab-public-pull', 'harbor-cloudlab-public-push', 'github-release-public'}
    externals = (get('externalsecrets', namespace=pool_namespace) or {}).get('items', [])
    if any(obj['spec'].get('secretStoreRef') != {'name': 'cloudlab', 'kind': 'ClusterSecretStore'} or
           obj['spec'].get('data') or any('extract' not in row for row in obj['spec'].get('dataFrom', [])) for obj in externals):
        raise RuntimeError('Public runner credentials require only their scoped vault items')
    items = {row['extract']['key'] for obj in externals
             for row in obj['spec'].get('dataFrom', []) if 'extract' in row}
    if (len(sets) != 2 or any(obj['spec'].get('maxRunners') != 1 for obj in sets) or
            not quota or any(quota['spec']['hard'].get(key) != value for key, value in
                             {'pods': '1', 'limits.cpu': '3', 'limits.memory': '6Gi'}.items()) or items != allowed):
        raise RuntimeError('Public runner quota or credential boundary differs from its approved contract')
    namespaces = [obj['metadata']['name'] for obj in (get('namespace') or {}).get('items', [])]
    if pool_namespace not in namespaces or len(namespaces) > 128:
        raise RuntimeError('Public runner secret proof requires its bounded live namespace inventory')
    for account in {obj['spec']['template']['spec']['serviceAccountName'] for obj in sets}:
        for namespace in namespaces:
            result = kube('auth', 'can-i', 'get', 'secrets', '-n', namespace,
                          '--as=system:serviceaccount:' + pool_namespace + ':' + account,
                          '--as-group=system:serviceaccounts', '--as-group=system:serviceaccounts:' + pool_namespace,
                          '--as-group=system:authenticated', allow_failure=True)
            if result.returncode != 1 or result.stdout.strip() != 'no':
                raise RuntimeError('Public runner service account secret denial was not proven')


def remote(request):
    sys.path.insert(0, '/opt/cloudlab')
    from playbooks.istio.files.kube import condition, get, kube, wait
    from playbooks.services.files.remote import inspect
    entry, action = request['entry'], request['action']
    approval = entry['approval']
    namespace = approval['namespace']
    policy = get('policy.kyverno.io', 'application-artifacts', namespace)
    if (not policy or not policy['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-services:') or
            policy['spec']['validationFailureAction'] != approval['artifact']['action']):
        raise RuntimeError('Application signature policy has not converged at its approved mode')
    if action == 'inspect':
        inspect({'action': 'backend', 'definition': entry['definition'], 'approval': approval})
        if approval['artifact']['project'] == 'cloudlab-public':
            public_pool(approval)
        application = get('application.argoproj.io', approval['name'] + '-' + entry['definition']['name'], 'argocd')
        return {key: application['metadata']['annotations']['cloudlab.io/' + field] for key, field in (
            ('digest', 'artifact-digest'), ('source_revision', 'source-revision'), ('workflow_run_id', 'workflow-run'))}
    if action != 'admission':
        raise ValueError('Unsupported application release proof')
    pod = copy.deepcopy(request['pod'])
    if (pod.get('apiVersion') != 'v1' or pod.get('kind') != 'Pod' or
            pod.get('metadata', {}).get('namespace') != namespace):
        raise ValueError('Admission proof requires its approved Pod namespace')
    nonce = secrets.token_hex(6)
    pod_name, name = 'artifact-proof-' + nonce, 'artifact-release-proof'
    fixture = isolated_policy(policy, pod_name, nonce)
    previous = get('policy.kyverno.io', name, namespace)
    if previous:
        labels = previous['metadata'].get('labels', {})
        old_nonce = labels.get('cloudlab.io/fixture', '')
        matches = [match['resources'] for rule in previous['spec']['rules'] for match in rule['match']['any']]
        if (labels.get('cloudlab.io/owner') != 'application-release-proof' or not re.fullmatch('[a-f0-9]{12}', old_nonce) or
                previous['metadata'].get('ownerReferences') or previous['metadata'].get('finalizers') or not matches or
                any(match.get('names') != ['artifact-proof-' + old_nonce] or
                    match.get('selector') != {'matchLabels': {'cloudlab.io/release-proof': old_nonce}} for match in matches)):
            raise RuntimeError('Retained proof policy has a conflicting owner or scope; cleanup refused')
        kube('delete', 'policy.kyverno.io', name, '-n', namespace, '--wait=true')
    kube('create', '-f', '-', document=fixture)
    uid = get('policy.kyverno.io', name, namespace)['metadata']['uid']
    try:
        wait(lambda: (get('policy.kyverno.io', name, namespace) or {}).get('status', {}).get('ready') is True or
             condition(get('policy.kyverno.io', name, namespace), 'Ready'), 'isolated signature policy', timeout=90)
        pod['metadata'].update(name=pod_name, labels={'cloudlab.io/release-proof': nonce})
        pod['spec']['imagePullSecrets'] = [{'name': 'harbor-application-pull'}]
        for label, image, rule in request['images']:
            pod['spec']['containers'][0]['image'] = image
            result = kube('create', '--dry-run=server', '-f', '-', document=pod, allow_failure=True)
            if rule is None:
                if result.returncode:
                    raise RuntimeError('Approved signed application did not pass isolated admission')
            elif not result.returncode or rule not in result.stderr:
                raise RuntimeError('Application rejection did not reach its required signature or repository rule')
            elif re.search(r'UNAUTHORIZED|status code (?:401|403)|no such host|connection refused', result.stderr):
                raise RuntimeError('Registry transport failure cannot count as signature rejection')
        return {'signed_admitted': True, 'unsigned_denied': True, 'untrusted_signer_denied': True,
                'other_repository_denied': True, 'test_pods_created': 0}
    finally:
        actual = get('policy.kyverno.io', name, namespace)
        if actual and (actual['metadata']['uid'] != uid or actual['metadata'].get('labels', {}).get('cloudlab.io/fixture') != nonce or
                       actual['metadata'].get('labels', {}).get('cloudlab.io/owner') != 'application-release-proof'):
            raise RuntimeError('Proof policy ownership changed; cleanup refused')
        if actual:
            kube('delete', 'policy.kyverno.io', name, '-n', namespace, '--wait=true')


def on_node(client, request):
    from playbooks.access.files.preflight import ssh
    response = ssh('VM', client.values['VM_HOST'], 'python3 -c ' + shlex.quote(Path(__file__).read_text()) + ' --remote',
                   input=json.dumps(request), timeout=360, diagnostics=client.path / 'artifacts/application-diagnostics.txt')
    return json.loads(response)


def verify_signature(registry, reference, artifact, release, directory):
    from playbooks.ci.files.publisher import execute, NativeFailure
    if artifact['project'] == 'cloudlab-private':
        from playbooks.secrets.files.vault import fields
        verifier = directory / 'private-verifier.pub'
        verifier.write_text(fields('ci-private-verifier', ('public_key',))['public_key'])
        execute(['cosign', 'verify', '--insecure-ignore-tlog=true', '--key', str(verifier), reference], registry.environment)
        return
    for identity in artifact['identities']:
        try:
            execute(['cosign', 'verify', '--certificate-identity', identity,
                     '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
                     '--certificate-github-workflow-repository', artifact['sourceRepository'],
                     '--certificate-github-workflow-ref', 'refs/heads/main',
                     '--certificate-github-workflow-sha', release['source_revision'], reference], registry.environment)
            return
        except NativeFailure:
            pass
    raise RuntimeError('Application signature does not match any retained approved workflow identity')


def fixtures(registry, reference, directory):
    from playbooks.ci.files.publisher import execute
    repository = reference.split('@')[0]
    nonce = secrets.token_hex(8)
    images = []
    for name in ('unsigned', 'untrusted'):
        tag = repository + ':release-admission-' + name + '-' + nonce
        registry.command('mutate', reference, '--label', 'cloudlab.io/admission-proof=' + name + '-' + nonce, '--tag', tag)
        digest = registry.command('digest', tag).decode().strip()
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
            raise RuntimeError('Proof artifact requires its actual immutable digest')
        images.append(repository + '@' + digest)
    key, public, prefix = directory / 'untrusted.pem', directory / 'untrusted.pub', directory / 'untrusted'
    environment = dict(registry.environment, COSIGN_PASSWORD=secrets.token_urlsafe(48))
    execute(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(key)], environment)
    execute(['openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(public)], environment)
    execute(['cosign', 'import-key-pair', '--key', str(key), '--output-key-prefix', str(prefix)], environment)
    execute(['cosign', 'sign', '--yes', '--new-bundle-format=false', '--use-signing-config=false',
             '--tlog-upload=false', '--key', str(prefix.with_suffix('.key')), images[1]], environment)
    execute(['cosign', 'verify', '--insecure-ignore-tlog=true', '--key', str(public), images[1]], environment)
    return images


def prove(client, entry):
    from playbooks.admission.files.verify import probe
    from playbooks.harbor.files.registry import Registry
    from playbooks.harbor.files.node_pull import verify_nodes
    artifact = entry['approval']['artifact']
    project, name = artifact['project'], entry['approval']['name']
    repository = client.private['host'] + '/' + project + '/' + name
    if artifact['repository'] != repository:
        raise ValueError('Application proof cannot send credentials to an unapproved registry')
    release = on_node(client, {'action': 'inspect', 'entry': entry})
    reference = repository + '@' + release['digest']
    registry = Registry(client.private['host'], client.env, client.path / 'artifacts/application-diagnostics.txt')
    other_project = 'cloudlab-private' if project == 'cloudlab-public' else 'cloudlab-public'
    rows = client.reader.get('/api/v2.0/projects/' + other_project + '/repositories/bootstrap/artifacts?page_size=1')
    if not rows or not re.fullmatch(r'sha256:[a-f0-9]{64}', rows[0]['digest']):
        raise RuntimeError('Project isolation requires an existing artifact in the other project')
    forbidden = client.private['host'] + '/' + other_project + '/bootstrap@' + rows[0]['digest']
    with tempfile.TemporaryDirectory(prefix='application-admission-') as temporary:
        directory = Path(temporary)
        with registry.identity(client.private['robots'][project + '-pull']):
            if registry.command('digest', reference).decode().strip() != release['digest']:
                raise RuntimeError('Approved application artifact is not obtainable')
            verify_signature(registry, reference, artifact, release, directory)
            registry.command('digest', forbidden, denied=True)
        with registry.identity(client.private['robots'][project + '-push']):
            unsigned, untrusted = fixtures(registry, reference, directory)
        with registry.identity(client.private['robots'][project + '-pull']):
            for image in (unsigned, untrusted):
                if registry.command('digest', image).decode().strip() != image.split('@')[1]:
                    raise RuntimeError('Signature rejection requires an existing readable proof artifact')
        admitted = on_node(client, {'action': 'admission', 'entry': entry,
            'pod': probe(entry['approval']['namespace']), 'images': [
            ['signed', reference, None], ['unsigned', unsigned, 'trusted-signature'],
            ['untrusted', untrusted, 'trusted-signature'], ['other-project', forbidden, 'approved-repositories']]})
    pulls = verify_nodes(client, {'projects': {project: {'repository': name, 'digest': release['digest']}}})
    if pulls != 2:
        raise RuntimeError('Application image must pull by digest on both node host networks')
    return dict(admitted, node_digest_pulls=pulls, cross_project_pull_denied=True,
                fixture_artifacts_retained=True, production_policy_changed=False,
                public_pool_secret_denial=project == 'cloudlab-public')


def main():
    from playbooks.infrastructure.files.harbor import Client, WORK
    from playbooks.services.files.inputs import catalog
    os.umask(0o077)
    entries = [entry for entry in catalog(required=True)['catalog']
               if entry['publication'] != 'retired' and entry['approval'].get('artifact')]
    if not entries:
        raise ValueError('Application proof requires an approved converged artifact release')
    with (WORK / 'client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        client = Client()
        with client.connected():
            results = [prove(client, entry) for entry in entries]
        print(json.dumps({'applications': len(results), 'checks': results}, sort_keys=True))


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--remote']:
            print(json.dumps(remote(json.load(sys.stdin)), sort_keys=True))
        elif not sys.argv[1:]:
            main()
        else:
            raise ValueError('Unsupported application proof arguments')
    except Exception as error:
        print(json.dumps({'exception': type(error).__name__, 'frames': [
            {'file': Path(frame.filename).name, 'line': frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__)]}), file=sys.stderr)
        raise SystemExit('Application release proof incomplete (' + type(error).__name__ +
                         '); production policy, credentials and data preserved') from None
