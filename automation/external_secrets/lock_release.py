"""Maintenance only: vendor an explicit chart release and pin its container image.

Requires Helm on PATH. Normal Compose applies use only the checked artifacts.
"""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent


def read(url, headers=None):
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def main(version):
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise SystemExit('Expected an explicit stable X.Y.Z release')
    url = f'https://github.com/external-secrets/external-secrets/releases/download/helm-chart-{version}/external-secrets-{version}.tgz'
    chart = read(url)
    with tempfile.TemporaryDirectory() as directory:
        archive = Path(directory) / 'chart.tgz'
        archive.write_bytes(chart)
        upstream = subprocess.check_output([
            'helm', 'template', 'external-secrets', str(archive), '--namespace', 'external-secrets',
            '--kube-version', '1.37.1', '--include-crds', '-f', str(ROOT / 'values.json')])
    image = f'ghcr.io/external-secrets/external-secrets:v{version}'
    token = json.loads(read('https://ghcr.io/token?service=ghcr.io&scope=repository:external-secrets/external-secrets:pull'))['token']
    manifest = read(f'https://ghcr.io/v2/external-secrets/external-secrets/manifests/v{version}', {
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json'})
    platforms = {item.get('platform', {}).get('architecture')
                 for item in json.loads(manifest).get('manifests', [])}
    if not {'amd64', 'arm64'} <= platforms:
        raise ValueError('ESO image must support amd64 and arm64')
    lock = dict(version=version, chart_url=url, chart_sha256=hashlib.sha256(chart).hexdigest(),
                helm=subprocess.check_output(['helm', 'version', '--short'], text=True).strip(),
                sha256=hashlib.sha256(upstream).hexdigest(),
                images={image: 'sha256:' + hashlib.sha256(manifest).hexdigest()})
    (ROOT / 'upstream.yaml').write_bytes(upstream)
    (ROOT / 'release.json').write_text(json.dumps(lock, indent=2) + '\n', encoding='utf-8')
    print('Locked ESO ' + version)


if __name__ == '__main__':
    main(sys.argv[1])
