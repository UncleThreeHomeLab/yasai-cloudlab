"""Build the pinned native provider with preserved legacy policy identities."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import urllib.request
import zipfile


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def extract(pin, destination):
    data = urllib.request.urlopen(pin['url'], timeout=120).read()
    if checksum(data) != pin['sha256']:
        raise RuntimeError('Provider build input checksum mismatch')
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(destination, filter='data')


def main():
    here = Path(__file__).parent
    pin = json.loads((here / 'cloudflare-provider.lock.json').read_text())
    patch = here / 'cloudflare-legacy.patch'
    if checksum(patch.read_bytes()) != pin['patch_sha256']:
        raise RuntimeError('Reviewed provider patch checksum mismatch')
    build = Path('/build')
    extract(pin['go'], build / 'compiler')
    extract(pin['source'], build / 'source')
    source = next((build / 'source').iterdir())
    subprocess.run(['git', 'apply', str(patch)], cwd=source, check=True)
    go = build / 'compiler/go/bin/go'
    env = dict(os.environ, GOTOOLCHAIN='local', CGO_ENABLED='0', GOOS='linux', GOARCH='amd64', GOMAXPROCS='4')
    env['PATH'] = str(go.parent) + ':' + env['PATH']
    subprocess.run([str(go), 'mod', 'download'], cwd=source, env=env, check=True)
    subprocess.run([str(go), 'mod', 'verify'], cwd=source, env=env, check=True)
    application = source / 'internal/services/zero_trust_access_application'
    tests = [str(path.relative_to(source)) for path in sorted(application.glob('*.go'))
             if not path.name.endswith('_test.go') or path.name == 'legacy_import_test.go']
    subprocess.run([str(go), 'test', '-p=6', '-mod=readonly', *tests,
                    '-run', 'Test(LegacyImport|ReusableImport)', '-count=1'], cwd=source, env=env, check=True)
    package = Path('/provider-package')
    package.mkdir(exist_ok=True)
    binary = package / ('terraform-provider-cloudflare_v' + pin['version'])
    subprocess.run([str(go), 'build', '-p=6', '-mod=readonly', '-trimpath', '-buildvcs=false',
                    '-ldflags=-s -w -buildid= -X main.version=' + pin['version'], '-o', str(binary), '.'],
                   cwd=source, env=env, check=True)
    mirror = Path('/provider-mirror/registry.opentofu.org/cloudlab/cloudflare')
    mirror.mkdir(parents=True, exist_ok=True)
    archive_path = mirror / ('terraform-provider-cloudflare_' + pin['version'] + '_linux_amd64.zip')
    with zipfile.ZipFile(archive_path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data, mode in ((binary.name, binary.read_bytes(), 0o755),
                                 ('LICENSE', (source / 'LICENSE').read_bytes(), 0o644)):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    actual = checksum(archive_path.read_bytes())
    print(json.dumps({'provider_package_sha256': actual}), flush=True)
    if sys.argv[1:] != ['--review'] and actual != pin['package_sha256']:
        raise RuntimeError('Built provider differs from its reviewed package checksum')


if __name__ == '__main__':
    main()
