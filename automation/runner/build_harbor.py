"""Build the pinned native Harbor provider with quota refresh and error handling."""
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

from build_cloudflare import checksum, extract


def main():
    here = Path(__file__).parent
    pin = json.loads((here / 'harbor-provider.lock.json').read_text())
    patch = here / 'harbor-quota.patch'
    if checksum(patch.read_bytes()) != pin['patch_sha256']:
        raise RuntimeError('Reviewed Harbor provider patch checksum mismatch')
    build = Path('/harbor-build')
    extract(pin['go'], build / 'compiler')
    extract(pin['source'], build / 'source')
    source = next((build / 'source').iterdir())
    subprocess.run(['git', 'apply', str(patch)], cwd=source, check=True)
    go = build / 'compiler/go/bin/go'
    env = dict(os.environ, GOTOOLCHAIN='local', CGO_ENABLED='0', GOOS='linux', GOARCH='amd64', GOMAXPROCS='4')
    env['PATH'] = str(go.parent) + ':' + env['PATH']
    for arguments in (('mod', 'download'), ('mod', 'verify'),
                      ('test', '-p=6', '-mod=readonly', './provider', '-run', '^TestCloudlabQuota', '-count=1')):
        subprocess.run([str(go), *arguments], cwd=source, env=env, check=True)
    binary = build / ('terraform-provider-harbor_v' + pin['version'])
    subprocess.run([str(go), 'build', '-p=6', '-mod=readonly', '-trimpath', '-buildvcs=false',
                    '-ldflags=-s -w -buildid= -X main.version=' + pin['version'], '-o', str(binary), '.'],
                   cwd=source, env=env, check=True)
    mirror = Path('/provider-mirror/registry.opentofu.org/cloudlab/harbor')
    mirror.mkdir(parents=True, exist_ok=True)
    destination = mirror / ('terraform-provider-harbor_' + pin['version'] + '_linux_amd64.zip')
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data, mode in ((binary.name, binary.read_bytes(), 0o755),
                                 ('LICENSE', (source / 'LICENSE').read_bytes(), 0o644)):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    actual = checksum(destination.read_bytes())
    print(json.dumps({'harbor_provider_package_sha256': actual}), flush=True)
    if sys.argv[1:] != ['--review'] and actual != pin['package_sha256']:
        raise RuntimeError('Built Harbor provider differs from its reviewed package checksum')


if __name__ == '__main__':
    main()
