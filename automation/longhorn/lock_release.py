"""Explicit maintenance command: download a release and lock every image.

Run through Compose with this directory mounted writable. Review the resulting
diff, then run syntax, unit tests and prove. Normal applies do not run this tool.
"""

import concurrent.futures
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request


ROOT = Path(__file__).resolve().parent


def read(url, headers=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=60) as response:
        return response.read()


def digest(image):
    repository, tag = image.removeprefix('docker.io/').split(':')
    token = json.loads(read('https://auth.docker.io/token?service=registry.docker.io&scope=repository:'
                            + repository + ':pull'))['token']
    content = read('https://registry-1.docker.io/v2/' + repository + '/manifests/' + tag,
                   {'Authorization': 'Bearer ' + token,
                    'Accept': 'application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json'})
    manifest = json.loads(content)
    architectures = {item.get('platform', {}).get('architecture') for item in manifest.get('manifests', [])}
    if not {'amd64', 'arm64'} <= architectures:
        raise ValueError('Image must support Linux amd64 and arm64: ' + image)
    return image, 'sha256:' + hashlib.sha256(content).hexdigest()


if __name__ == '__main__':
    version = sys.argv[1]
    if not re.fullmatch(r'v\d+\.\d+\.\d+', version):
        raise SystemExit('Expected an explicit stable vX.Y.Z release')
    url = 'https://raw.githubusercontent.com/longhorn/longhorn/' + version + '/deploy/longhorn.yaml'
    upstream = read(url)
    images = sorted(set(re.findall(r'docker\.io/longhornio/[a-z0-9-]+:[a-zA-Z0-9_.-]+', upstream.decode())))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        locked = dict(pool.map(digest, images))
    (ROOT / 'upstream.yaml').write_bytes(upstream)
    (ROOT / 'release.json').write_text(json.dumps(dict(version=version, url=url,
        sha256=hashlib.sha256(upstream).hexdigest(), images=locked), indent=2) + '\n', encoding='utf-8')
    print('Locked', version, 'and', len(locked), 'multi-architecture images.')
