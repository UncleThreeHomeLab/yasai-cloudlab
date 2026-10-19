"""Fail closed when the API or either declared lab node cannot support a build."""
import json
from pathlib import Path
import re
import ssl
import sys
import urllib.request

FILES = Path('/var/run/cloudlab-health')
SERVER = 'https://kubernetes.default.svc'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def nodes_ready(document):
    if not isinstance(document, dict):
        return False
    metadata = document.get('metadata', {})
    if not isinstance(metadata, dict) or metadata.get('continue'):
        return False
    nodes = document.get('items')
    if not isinstance(nodes, list) or len(nodes) != 2:
        return False
    names = set()
    for node in nodes:
        if not isinstance(node, dict):
            return False
        metadata = node.get('metadata', {})
        name = metadata.get('name') if isinstance(metadata, dict) else None
        if not isinstance(name, str) or not name or name in names or metadata.get('deletionTimestamp'):
            return False
        names.add(name)
        status = node.get('status', {})
        if not isinstance(status, dict):
            return False
        rows = status.get('conditions', [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) or
                not isinstance(row.get('type'), str) or not isinstance(row.get('status'), str) for row in rows):
            return False
        conditions = {row.get('type'): row.get('status') for row in rows}
        if len(conditions) != len(rows) or conditions.get('Ready') != 'True':
            return False
        if any(conditions.get(name) != 'False' for name in ('MemoryPressure', 'DiskPressure', 'PIDPressure')):
            return False
        if conditions.get('NetworkUnavailable', 'False') != 'False':
            return False
    return True


def check(directory=FILES):
    token = (directory / 'token').read_text().strip()
    if len(token) > 16384 or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token):
        raise ValueError('Invalid health credential')
    context = ssl.create_default_context(cafile=str(directory / 'ca.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=context), NoRedirect())
    def request(path, limit):
        query = urllib.request.Request(SERVER + path, headers={'Authorization': 'Bearer ' + token})
        with opener.open(query, timeout=2) as response:
            if response.status != 200:
                raise ValueError('Health API unavailable')
            data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError('Health response too large')
            return data
    if request('/readyz', 1024).strip() != b'ok':
        return False
    return nodes_ready(json.loads(request('/api/v1/nodes?limit=3', 1024 * 1024)))


def main():
    try:
        if check():
            return 0
    except Exception:
        pass
    print('CI node health check failed.', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
