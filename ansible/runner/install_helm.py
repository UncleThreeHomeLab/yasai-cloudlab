"""Install the checksum-verified Helm tool during the runner build."""

import hashlib
import io
import json
from pathlib import Path
import platform
import tarfile
import urllib.request

lock = json.loads(Path(__file__).with_name('helm.lock.json').read_text())
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
url = f"https://get.helm.sh/helm-{lock['version']}-linux-{arch}.tar.gz"
with urllib.request.urlopen(url, timeout=60) as response:
    data = response.read()
if hashlib.sha256(data).hexdigest() != lock['sha256'][arch]:
    raise SystemExit('Helm archive checksum mismatch')
with tarfile.open(fileobj=io.BytesIO(data)) as archive:
    binary = archive.extractfile(f'linux-{arch}/helm').read()
target = Path('/usr/local/bin/helm')
target.write_bytes(binary)
target.chmod(0o755)
