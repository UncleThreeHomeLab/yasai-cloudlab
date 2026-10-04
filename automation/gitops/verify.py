"""Disposable public GitOps authorization and network checks; no private output."""
import json
import fcntl
import os
import re
import sys
import time
import uuid
from bootstrap import BASE, kube, get, wait_application
from controller_stability import fingerprint


def wait_result(function, description, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if function():
            return
        time.sleep(3)
    raise RuntimeError(description + ' did not pass before its deadline')


def pod(namespace, name, image, command, trusted=False):
    labels = {'cloudlab.io/verification': 'gitops'}
    if trusted:
        labels['app.kubernetes.io/part-of'] = 'argocd'
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace, 'labels': labels},
        'spec': {'restartPolicy': 'Never', 'automountServiceAccountToken': False,
            'activeDeadlineSeconds': 120,
            'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'seccompProfile': {'type': 'RuntimeDefault'}},
            'containers': [{'name': 'probe', 'image': image, 'command': ['sh', '-ec', command],
                'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'memory': '32Mi'}},
                'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}}]}}


def verify_pod(document):
    namespace, name = document['metadata']['namespace'], document['metadata']['name']
    kube('create', '-f', '-', document=document)
    try:
        def ready():
            result = json.loads(kube('get', 'pod', name, '-n', namespace, '-o', 'json'))
            phase = result.get('status', {}).get('phase')
            if phase == 'Failed':
                # Inspect privately before cleanup; expose only bounded categories.
                logs = kube('logs', name, '-n', namespace)
                categories = []
                for label, pattern in (
                    ('timeout', r'timed out'), ('refused', r'connection refused'),
                    ('http-denial', r'HTTP/[0-9.]+ (401|403)'),
                    ('tls-error', r'handshake|SSL|TLS|certificate'),
                    ('tool-option', r'unrecognized option|invalid option'),
                    ('dns-error', r'bad address|NXDOMAIN'),
                    ('route-denial', r'No route to host'),
                    ('tls-connected', r'CONNECTION ESTABLISHED|Protocol version:'),
                ):
                    if re.search(pattern, logs, re.I):
                        categories.append(label)
                trusted = document['metadata']['labels'].get('app.kubernetes.io/part-of') == 'argocd'
                raise RuntimeError('GitOps ' + ('allowed' if trusted else 'denied') +
                    ' fixture failed; diagnostic categories: ' + ','.join(categories or ['none']))
            return phase == 'Succeeded'
        wait_result(ready, 'GitOps network/authentication fixture')
    finally:
        kube('delete', 'pod', name, '-n', namespace, '--ignore-not-found', '--wait=true', '--timeout=60s')


def denied_application(payload, case, suffix):
    name = 'cloudlab-denied-' + case + '-' + suffix
    app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': name, 'namespace': 'argocd', 'labels': {'cloudlab.io/verification': 'gitops'}},
        'spec': {'project': 'cloudlab-public',
            'source': {'repoURL': payload['repository'], 'targetRevision': payload['revision'], 'path': 'gitops/fixtures/public'},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': payload['public_namespace']}}}
    if case == 'source':
        app['spec']['source']['repoURL'] = 'https://github.com/example/forbidden.git'
        expected = 'is not permitted in project'
    else:
        app['spec']['destination']['namespace'] = 'argocd'
        expected = 'do not match any of the allowed destinations'
    kube('create', '-f', '-', document=app)
    try:
        def rejected():
            current = get('application.argoproj.io', name)
            return any(c['type'] == 'InvalidSpecError' and expected in c.get('message', '')
                       for c in (current or {}).get('status', {}).get('conditions', []))
        wait_result(rejected, 'AppProject ' + case + ' denial')
    finally:
        kube('delete', 'application.argoproj.io', name, '-n', 'argocd', '--ignore-not-found', '--wait=true')


def public_lifecycle(payload):
    name, namespace = 'cloudlab-public-fixture', payload['public_namespace']
    def configmap():
        text = kube('get', 'configmap', name, '-n', namespace, '--ignore-not-found', '-o', 'json')
        return json.loads(text) if text.strip() else None
    previous = [get('application.argoproj.io', name), configmap()]
    if any(x and x['metadata'].get('labels', {}).get('cloudlab.io/verification') != 'gitops-public-fixture' for x in previous):
        raise RuntimeError('Public fixture name is already owned by another actor')
    if previous[0]:
        spec = previous[0]['spec']
        if (spec.get('project') != 'cloudlab-public' or
                spec.get('source', {}).get('repoURL') != payload['repository'] or
                spec.get('source', {}).get('path') not in ('gitops/fixtures/public', 'gitops/fixtures/intentionally-missing') or
                spec.get('destination', {}).get('namespace') != namespace):
            raise RuntimeError('Existing public fixture configuration has a different owner')
    app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': name, 'namespace': 'argocd', 'labels': {'cloudlab.io/verification': 'gitops-public-fixture'}},
        'spec': {'project': 'cloudlab-public', 'source': {'repoURL': payload['repository'],
            'targetRevision': payload['revision'], 'path': 'gitops/fixtures/public'},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': namespace},
            'syncPolicy': {'automated': {'prune': False, 'selfHeal': True, 'allowEmpty': False},
                           'syncOptions': ['FailOnSharedResource=true']}}}
    kube('apply', '--server-side', '--field-manager=cloudlab-gitops-verifier', '-f', '-', document=app)
    try:
        wait_application(name, payload['revision'])
        initial = configmap()
        if not initial:
            raise RuntimeError('Public fixture did not reconcile')
        uid, data = initial['metadata']['uid'], initial['data']
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': uid},
                 {'op': 'replace', 'path': '/data/purpose', 'value': 'intentional verification drift'}]
        kube('patch', 'configmap', name, '-n', namespace, '--type=json', '--patch-file=/dev/stdin', document=patch)
        wait_result(lambda: (configmap() or {}).get('data') == data, 'Public GitOps drift repair')
        app['spec']['source']['path'] = 'gitops/fixtures/intentionally-missing'
        kube('apply', '--server-side', '--field-manager=cloudlab-gitops-verifier', '-f', '-', document=app)
        wait_result(lambda: any(c['type'] == 'ComparisonError' for c in get('application.argoproj.io', name).get('status', {}).get('conditions', [])),
                    'Public source failure reporting')
        if configmap()['metadata']['uid'] != uid or configmap()['data'] != data:
            raise RuntimeError('Source failure changed the retained public workload')
        kube('delete', 'application.argoproj.io', name, '-n', 'argocd', '--wait=true')
        if configmap()['metadata']['uid'] != uid:
            raise RuntimeError('Application removal did not retain the public workload')
    finally:
        kube('delete', 'application.argoproj.io', name, '-n', 'argocd', '--ignore-not-found', '--wait=true')
        current = configmap()
        if current and current['metadata'].get('labels', {}).get('cloudlab.io/verification') == 'gitops-public-fixture':
            kube('delete', 'configmap', name, '-n', namespace, '--wait=true')


def controllers(payload):
    items = json.loads(kube('get', 'deployments,daemonsets,statefulsets,pods', '-n', 'argocd', '-o', 'json'))['items']
    for obj in items:
        if obj['kind'] == 'Pod' and obj.get('status', {}).get('phase') != 'Succeeded':
            containers = obj['spec'].get('containers', []) + obj['spec'].get('initContainers', [])
            if any(c['image'] not in payload['image_refs'] for c in containers):
                raise RuntimeError('Argo runtime image differs from the committed digest lock')
    return fingerprint(items)


def run(payload):
    for name in ('cloudlab-public-root', 'cloudlab-argocd'):
        wait_application(name, payload['revision'])
    default = get('appproject.argoproj.io', 'default')['spec']
    if default.get('sourceRepos') or default.get('destinations'):
        raise RuntimeError('Default Argo project grants unexpected access')
    suffix = uuid.uuid4().hex[:10]
    for case in ('source', 'namespace'):
        denied_application(payload, case, suffix)
    public_lifecycle(payload)
    # These unauthenticated probes test reachability and HTTP denial, not PKI.
    # They send no credentials. Certificate validation is a separate milestone.
    endpoint = 'argocd-server.argocd.svc'
    def request(path):
        return ("status=0; printf 'GET " + path + " HTTP/1.1\\r\\nHost: " + endpoint +
            "\\r\\nConnection: close\\r\\n\\r\\n' | timeout 10 openssl s_client -quiet -connect " +
            endpoint + ':443 -servername ' + endpoint + ' >/tmp/response 2>/tmp/tls || status=$?; '
            'if test $status -eq 124; then echo timed out; exit 1; fi; ')
    # Reuse the digest-locked Argo image's complete OpenSSL client. The minimal
    # BusyBox TLS client is not a reliable oracle for the Argo TLS configuration.
    # Pod IP selectors may lag container startup briefly. Retry only this
    # positive readiness probe, still requiring both real HTTP responses.
    allowed = ("for attempt in 1 2 3 4; do if (" + request('/healthz') +
        "grep -Eq '^HTTP/[0-9.]+ 200' /tmp/response) && (" +
        request('/api/v1/applications') + "grep -Eq '^HTTP/[0-9.]+ (401|403)' /tmp/response); " +
        "then exit 0; fi; sleep 3; done; cat /tmp/tls; exit 1")
    verify_pod(pod('argocd', 'cloudlab-allowed-' + suffix, payload['probe_image'], allowed, trusted=True))
    denied = ('getent hosts ' + endpoint + ' >/dev/null || { echo NXDOMAIN; exit 1; }; status=0; '
        'timeout 6 openssl s_client -brief -connect ' + endpoint + ':443 -servername ' + endpoint +
        ' </dev/null >/tmp/response 2>/tmp/tls || status=$?; '
        'cat /tmp/tls; '
        "if grep -Eq 'CONNECTION ESTABLISHED|Protocol version:' /tmp/tls; then exit 1; fi; "
        "test $status -eq 124 || { test $status -ne 0 && grep -Eiq 'Connection refused|No route to host' /tmp/tls; }")
    verify_pod(pod(payload['public_namespace'], 'cloudlab-denied-' + suffix, payload['probe_image'], denied))
    before = {name: get('application.argoproj.io', name)['metadata']['uid']
              for name in ('cloudlab-public-root', 'cloudlab-argocd')}
    stable_controllers = controllers(payload)
    started = time.monotonic()
    while time.monotonic() - started < 60:
        time.sleep(10)
        if controllers(payload) != stable_controllers:
            raise RuntimeError('Argo controller or pod changed during stability observation')
        for name, uid in before.items():
            current = get('application.argoproj.io', name)
            status = current.get('status', {})
            if (current['metadata']['uid'] != uid or status.get('sync', {}).get('status') != 'Synced' or
                    status.get('sync', {}).get('revision') != payload['revision'] or
                    status.get('health', {}).get('status') != 'Healthy'):
                raise RuntimeError('Public GitOps did not remain converged')
    result = {'public_roots_converged': True, 'source_denied': True, 'namespace_denied': True,
                      'unauthenticated_api_denied': True, 'untrusted_network_denied': True,
                      'public_drift_repaired': True, 'public_source_failure_retained': True,
                      'public_removal_retained': True, 'controllers_stable': True,
              'stability_seconds': round(time.monotonic() - started, 1), 'private_sources_tested': False}
    receipt = BASE / 'public-proof.tmp'
    with receipt.open('w') as stream:
        json.dump(dict(result, revision=payload['revision'], verified_at=time.time()), stream)
        stream.flush()
        os.fsync(stream.fileno())
    receipt.replace(BASE / 'public-proof.json')
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        os.umask(0o077)
        with (BASE / 'verification.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            run(json.load(sys.stdin))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else 'GitOps verification failed; private output withheld') from None
