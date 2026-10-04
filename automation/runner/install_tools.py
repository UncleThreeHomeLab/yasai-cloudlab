"""Install checked bootstrap binaries; no lab service is required."""
import bz2
import hashlib
import io
import json
from pathlib import Path
import platform
import urllib.request
import zipfile

if platform.machine() not in ('x86_64', 'AMD64'):
    raise SystemExit('Use the declared linux/amd64 Compose runner.')
for name, pin in json.loads(Path(__file__).with_name('tools.lock.json').read_text()).items():
    data = urllib.request.urlopen(pin['url'], timeout=120).read()
    if hashlib.sha256(data).hexdigest() != pin['sha256']:
        raise SystemExit('Tool artifact checksum mismatch: ' + name)
    binary = (zipfile.ZipFile(io.BytesIO(data)).read(name)
              if pin['url'].endswith('.zip') else bz2.decompress(data))
    target = Path('/usr/local/bin') / name
    target.write_bytes(binary)
    target.chmod(0o755)
