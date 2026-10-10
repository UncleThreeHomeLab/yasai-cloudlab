"""One bounded realm writer across scheduled and Argo sync jobs."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request

DURATION = 240
OWNER = 'cloudlab-identity-writer'


def owned_lease(request, namespace, endpoint):
    try:
        current = request('GET')
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        value = {'apiVersion': 'coordination.k8s.io/v1', 'kind': 'Lease',
                 'metadata': {'name': 'identity-writer', 'namespace': namespace,
                              'labels': {'cloudlab.io/owner': OWNER}}, 'spec': {}}
        try:
            current = request('POST', value, url=endpoint.rsplit('/', 1)[0])
        except urllib.error.HTTPError as conflict:
            if conflict.code != 409:
                raise
            current = request('GET')
    metadata = current.get('metadata', {})
    if (metadata.get('name') != 'identity-writer' or metadata.get('namespace') != namespace or
            metadata.get('labels', {}).get('cloudlab.io/owner') != OWNER or
            not metadata.get('uid') or not metadata.get('resourceVersion') or
            metadata.get('ownerReferences') or metadata.get('deletionTimestamp') or metadata.get('finalizers')):
        raise RuntimeError('Identity writer lease has conflicting ownership')
    return current


def available(spec, now):
    renewed = spec.get('renewTime') or spec.get('acquireTime')
    if not spec.get('holderIdentity'):
        return True
    if not renewed:
        return False
    instant = datetime.fromisoformat(renewed.replace('Z', '+00:00')).timestamp()
    return now >= instant + spec['leaseDurationSeconds']


def previous_writer_done(spec, pods):
    holder = spec.get('holderIdentity')
    return not any(pod['metadata']['uid'] == holder and pod.get('status', {}).get('phase')
                   not in ('Succeeded', 'Failed') for pod in pods)


def api_request(method, url, value=None):
    account = Path('/var/run/secrets/kubernetes.io/serviceaccount')
    context = ssl.create_default_context(cafile=str(account / 'ca.crt'))
    headers = {'Authorization': 'Bearer ' + account.joinpath('token').read_text().strip(),
               'Content-Type': 'application/json'}
    req = urllib.request.Request(url, data=json.dumps(value).encode() if value else None,
                                 method=method, headers=headers)
    with urllib.request.urlopen(req, context=context, timeout=10) as response:
        return json.load(response)


def offline_guard(uid):
    namespace = Path('/var/run/secrets/kubernetes.io/serviceaccount').joinpath('namespace').read_text().strip()
    origin = 'https://kubernetes.default.svc'
    server = api_request('GET', origin + '/apis/k8s.keycloak.org/v2beta1/namespaces/' + namespace + '/keycloaks/cloudlab-keycloak')
    pods = api_request('GET', origin + '/api/v1/namespaces/' + namespace + '/pods')['items']
    if (server['metadata']['uid'] != uid or server['spec']['instances'] != 0 or any(
            pod['metadata'].get('labels', {}).get('app') == 'keycloak' and
            pod.get('status', {}).get('phase') not in ('Succeeded', 'Failed') for pod in pods)):
        raise RuntimeError('Offline recovery requires the unchanged stopped server and no active server Pods')


def acquire(skip_busy=False):
    namespace = Path('/var/run/secrets/kubernetes.io/serviceaccount').joinpath('namespace').read_text().strip()
    endpoint = 'https://kubernetes.default.svc/apis/coordination.k8s.io/v1/namespaces/' + namespace + '/leases/identity-writer'
    request = lambda method, value=None, url=endpoint: api_request(method, url, value)

    # Argo CD always excludes Leases. The Argo job owns this operational lock.
    current = owned_lease(request, namespace, endpoint)
    now = datetime.now(timezone.utc)
    if not available(current.get('spec', {}), now.timestamp()):
        if skip_busy:
            return False
        raise RuntimeError('Another identity writer holds the lease')
    if current.get('spec', {}).get('holderIdentity'):
        pods = request('GET', url='https://kubernetes.default.svc/api/v1/namespaces/' + namespace +
                       '/pods')['items']
        if not previous_writer_done(current['spec'], pods):
            if skip_busy:
                return False
            raise RuntimeError('Previous writer has not stopped; expired lease cannot authorize overlap')
    stamp = now.isoformat().replace('+00:00', 'Z')
    current['spec'] = {'holderIdentity': os.environ['POD_UID'], 'leaseDurationSeconds': DURATION,
                       'acquireTime': stamp, 'renewTime': stamp,
                       'leaseTransitions': current.get('spec', {}).get('leaseTransitions', 0) + 1}
    # PUT retains resourceVersion; a competing acquisition returns HTTP 409.
    try:
        request('PUT', current)
    except urllib.error.HTTPError as error:
        if skip_busy and error.code == 409:
            return False
        raise
    return True


if __name__ == '__main__':
    try:
        acquire()
    except Exception:
        raise SystemExit('Identity writer lease unavailable; no realm changes made') from None
