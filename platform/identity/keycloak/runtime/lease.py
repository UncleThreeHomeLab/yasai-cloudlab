"""One bounded realm writer across scheduled and Argo sync jobs."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request

DURATION = 240


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


def acquire():
    account = Path('/var/run/secrets/kubernetes.io/serviceaccount')
    namespace = account.joinpath('namespace').read_text().strip()
    endpoint = 'https://kubernetes.default.svc/apis/coordination.k8s.io/v1/namespaces/' + namespace + '/leases/identity-writer'
    context = ssl.create_default_context(cafile=str(account / 'ca.crt'))
    headers = {'Authorization': 'Bearer ' + account.joinpath('token').read_text().strip(),
               'Content-Type': 'application/json'}

    def request(method, value=None, url=endpoint):
        req = urllib.request.Request(url, data=json.dumps(value).encode() if value else None,
                                     method=method, headers=headers)
        with urllib.request.urlopen(req, context=context, timeout=10) as response:
            return json.load(response)

    current = request('GET')
    now = datetime.now(timezone.utc)
    if not available(current.get('spec', {}), now.timestamp()):
        raise RuntimeError('Another identity writer holds the lease')
    if current.get('spec', {}).get('holderIdentity'):
        pods = request('GET', url='https://kubernetes.default.svc/api/v1/namespaces/' + namespace +
                       '/pods')['items']
        if not previous_writer_done(current['spec'], pods):
            raise RuntimeError('Previous writer has not stopped; expired lease cannot authorize overlap')
    stamp = now.isoformat().replace('+00:00', 'Z')
    current['spec'] = {'holderIdentity': os.environ['POD_UID'], 'leaseDurationSeconds': DURATION,
                       'acquireTime': stamp, 'renewTime': stamp,
                       'leaseTransitions': current.get('spec', {}).get('leaseTransitions', 0) + 1}
    # PUT retains resourceVersion; a competing acquisition returns HTTP 409.
    request('PUT', current)


if __name__ == '__main__':
    try:
        acquire()
    except Exception:
        raise SystemExit('Identity writer lease unavailable; no realm changes made') from None
