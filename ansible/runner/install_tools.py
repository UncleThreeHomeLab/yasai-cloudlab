"""Install checked bootstrap binaries; no lab service is required."""
import bz2
import hashlib
import io
import json
from pathlib import Path
import platform
import tarfile
import urllib.request
import zipfile

def binary(name, pin, data):
    if hashlib.sha256(data).hexdigest() != pin['sha256']:
        raise ValueError('Tool artifact checksum mismatch: ' + name)
    if pin['url'].endswith('.zip'):
        return zipfile.ZipFile(io.BytesIO(data)).read(name)
    if pin['url'].endswith('.bz2'):
        return bz2.decompress(data)
    if pin['url'].endswith('.tar.gz'):
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            member = archive.getmember(name)
            if not member.isfile():
                raise ValueError('Tool binary must be a regular archive member')
            return archive.extractfile(member).read()
    raise ValueError('Unsupported bootstrap tool archive')


if __name__ == '__main__':
    if platform.machine() not in ('x86_64', 'AMD64'):
        raise SystemExit('Use the declared linux/amd64 Compose runner.')
    for name, pin in json.loads(Path(__file__).with_name('tools.lock.json').read_text()).items():
        data = urllib.request.urlopen(pin['url'], timeout=120).read()
        target = Path('/usr/local/bin') / name
        target.write_bytes(binary(name, pin, data))
        target.chmod(0o755)
