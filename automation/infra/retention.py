"""Bound encrypted GitLab history while retaining protected local recovery data."""
import base64
from datetime import datetime, timezone
import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid

MAX_BYTES = 8 * 1024**2
MAX_VERSIONS = 32


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def request(env, suffix='', method='GET', document=None):
    url = env['TF_HTTP_ADDRESS']
    if not re.fullmatch(r'https://gitlab[.]com/api/v4/projects/[1-9][0-9]*/terraform/state/(?:managed|qualification-[a-f0-9]{32})', url):
        raise ValueError('Retention requires the designated managed or disposable state backend')
    if not re.fullmatch(r'(?:/lock|/versions/[1-9][0-9]*)?', suffix) or method not in ('GET', 'POST', 'DELETE'):
        raise ValueError('Retention request escaped its designated state scope')
    if method == 'DELETE' and not suffix:
        raise ValueError('Retention cannot delete managed state')
    basic = base64.b64encode((env['TF_HTTP_USERNAME'] + ':' + env['TF_HTTP_PASSWORD']).encode()).decode()
    req = urllib.request.Request(url + suffix, method=method,
        headers={'Authorization': 'Basic ' + basic, 'Content-Type': 'application/json'},
        data=json.dumps(document).encode() if document is not None else None)
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=30) as response:
            return response.status, response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as error:
        return error.code, error.read(16 * 1024)


def ciphertext(env):
    status, raw = request(env)
    if status != 200 or len(raw) > MAX_BYTES or 'encrypted_data' not in json.loads(raw):
        raise RuntimeError('Encrypted state unavailable or exceeds the 8 MiB bound; maintenance required')
    return raw


def maintain(client):
    """Own a normal backend lock; never unlock another client's operation."""
    lock = {'ID': str(uuid.uuid4()), 'Operation': 'OperationTypeApply', 'Info': 'Encrypted version retention',
            'Who': 'independent-compose', 'Version': '1.13.1',
            'Created': datetime.now(timezone.utc).isoformat(), 'Path': 'managed'}
    if request(client.env, '/lock', 'POST', lock)[0] not in (200, 201):
        raise RuntimeError('Retention lock rejected; never force unlock')
    try:
        raw = ciphertext(client.env)
        pulled = client.native('state', 'pull')
        if pulled.returncode:
            raise RuntimeError('Retention cannot read current state; protected recovery data retained')
        current = json.loads(pulled.stdout)
        serial = current['serial']
        if type(serial) is not int or serial < 1:
            raise ValueError('Retention requires a positive native state serial')
        # Keep the latest exact encrypted state independently of GitLab; do not touch failure recovery files.
        protected = client.path / 'retained-state.encrypted'
        temporary = protected.with_suffix('.tmp')
        with temporary.open('wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(protected)
        cursor_path = client.path / 'retention.json'
        cursor = json.loads(cursor_path.read_text()) if cursor_path.exists() else {}
        previous = cursor.get('pruned_through', 0) if cursor.get('lineage') == current['lineage'] else 0
        if type(previous) is not int or not 0 <= previous < serial:
            raise ValueError('Retention cursor differs from native state; inspect before pruning')
        cutoff = max(0, serial - MAX_VERSIONS)
        for older in range(previous + 1, cutoff + 1):
            suffix = '/versions/' + str(older)
            status, protected = request(client.env, suffix)
            if status == 200:
                if len(protected) > MAX_BYTES or 'encrypted_data' not in json.loads(protected):
                    raise RuntimeError('Historical state exceeds its encrypted retention contract')
                if request(client.env, suffix, 'DELETE')[0] not in (200, 202, 204, 404):
                    raise RuntimeError('Scoped version pruning failed; current state remains protected')
                if request(client.env, suffix)[0] != 404:
                    raise RuntimeError('Version pruning pending; rerun maintenance after deletion completes')
            elif status != 404:
                raise RuntimeError('Historical state unavailable; pruning refused')
            cursor_path.write_text(json.dumps({'lineage': current['lineage'], 'pruned_through': older}))
        if ciphertext(client.env) != raw:
            raise RuntimeError('Current state changed under retention lock; inspect protected recovery data')
    finally:
        if request(client.env, '/lock', 'DELETE', lock)[0] not in (200, 204):
            raise RuntimeError('Owned retention lock could not be released; inspect it, never force unlock automatically')


def main():
    import fcntl
    from automation.infra.command import Client, ROOTS, WORK
    os.umask(0o077)
    if len(sys.argv) != 2 or sys.argv[1] not in ROOTS:
        raise ValueError('Specify the accepted cloudflare or github root for retention maintenance')
    root = sys.argv[1]
    WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (WORK / (root + '.lock')).open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Concurrent local maintenance rejected; never force unlock') from None
        client = Client(root)
        client.initialize()
        client.unchanged_inputs()
        maintain(client)
    print(json.dumps({'root': root, 'encrypted_history_bounded': True, 'maximum_versions': MAX_VERSIONS}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, KeyError, TypeError, OSError) as error:
        print(str(error) if isinstance(error, (ValueError, RuntimeError)) else
              'Retention maintenance incomplete; protected recovery retained', file=sys.stderr)
        raise SystemExit(1) from None
