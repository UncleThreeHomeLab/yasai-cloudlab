"""Complete bootstrap tool updates, with URLs derived from fixed upstreams."""
import json
import base64
from pathlib import Path
import re
import urllib.parse

from .security import archive_files, digest, download, owned_path
from .inputs import baseline

TOOLS = {
    'tofu': ('https://github.com/opentofu/opentofu/releases/download/',
             'v{version}/tofu_{version}_linux_amd64.zip'),
    'op': ('https://cache.agilebits.com/dist/1P/op2/pkg/',
           'v{version}/op_linux_amd64_v{version}.zip'),
    'restic': ('https://github.com/restic/restic/releases/download/',
               'v{version}/restic_{version}_linux_amd64.bz2'),
}


def provenance(root, plan, *, fetch=download):
    """Authenticate changed non-chart downloads, including unused architecture pins."""
    for relative, encoded in plan['baseFiles'].items():
        if relative == 'ansible/playbooks/k3s/vars.yml':
            import yaml
            before = yaml.safe_load(base64.b64decode(encoded, validate=True))
            after = yaml.safe_load(owned_path(root, relative).read_bytes())
            if before == after:
                continue
            version = urllib.parse.quote(after['k3s_version'], safe='')
            prefix = 'https://github.com/k3s-io/k3s/releases/download/'
            for machine, arch in (('x86_64', 'amd64'), ('aarch64', 'arm64')):
                pin = after['k3s_binaries'][machine]
                manifest = fetch(prefix + version + '/sha256sum-' + arch + '.txt', prefix=prefix).decode()
                hashes = re.findall(r'^([a-f0-9]{64})\s+\*?' + re.escape(pin['asset']) + r'$', manifest, re.M)
                if hashes != [pin['sha256']]:
                    raise ValueError('K3s checksum differs from its exact official release manifest')
            prefix = 'https://raw.githubusercontent.com/k3s-io/k3s/'
            if after['k3s_installer_checksum'] != 'sha256:' + digest(fetch(prefix + version + '/install.sh', prefix=prefix)):
                raise ValueError('K3s installer differs from its exact official release')
            continue
        if relative not in {'ansible/runner/tools.lock.json', 'ansible/runner/helm.lock.json',
                            'ansible/playbooks/tailscale/files/release.json',
                            'platform/delivery/rollouts/artifact.lock.json'}:
            continue
        before = json.loads(base64.b64decode(encoded, validate=True))
        after = json.loads(owned_path(root, relative).read_bytes())
        if before == after:
            continue
        if relative.endswith('/helm.lock.json'):
            for arch, sha in after['sha256'].items():
                if after['version'] == before['version'] and sha == before['sha256'][arch]:
                    continue
                url = 'https://get.helm.sh/helm-' + after['version'] + '-linux-' + arch + '.tar.gz'
                if digest(fetch(url, prefix='https://get.helm.sh/')) != sha:
                    raise ValueError('Helm architecture checksum differs from its official release')
            continue
        names = TOOLS if relative.endswith('/tools.lock.json') else ('plugin',) if '/rollouts/' in relative else (None,)
        for name in names:
            old, new = (before[name], after[name]) if name else (before, after)
            if old == new:
                continue
            # Compatibility.verify already binds the complete URL to original-base pins.
            if digest(fetch(new['url'], prefix=old['url'].rsplit('/', 1)[0].rsplit('/', 1)[0] + '/')) != new['sha256']:
                raise ValueError('Tool checksum differs from its exact official artifact')


def write_json(path, document):
    path.write_text(json.dumps(document, indent=2) + '\n', newline='\n')


def replace_exact(root, paths, old, new):
    """Update a known companion token; reject missing expected occurrences."""
    for relative in paths:
        path = owned_path(root, relative)
        text = path.read_text()
        if old not in text:
            raise ValueError('Required maintenance companion is missing: ' + relative)
        path.write_text(text.replace(old, new), newline='\n')


def update(root, name, version, *, fetch=download):
    if name == 'cmctl':
        return cmctl(root, version, fetch=fetch)
    if name == 'gateway-api-plugin':
        return gateway_plugin(root, version, fetch=fetch)
    if name == 'oauth2-proxy':
        return oauth2_proxy(root, version, fetch=fetch)
    if name == 'debian':
        return debian(root, version, fetch=fetch)
    if name == 'k3s':
        return k3s(root, version, fetch=fetch)
    if name not in (*TOOLS, 'helm', 'tailscale') or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('Unsupported tool or version')
    root = Path(root)
    relative = ('ansible/runner/tools.lock.json' if name in TOOLS else 'ansible/runner/helm.lock.json' if name == 'helm'
                else 'ansible/playbooks/tailscale/files/release.json')
    original = json.loads(baseline(root, relative))
    previous_version = original[name]['version'] if name in TOOLS else original['version'].lstrip('v')
    if version.split('.')[:2] != previous_version.split('.')[:2]:
        raise ValueError('Tool minor changes require separate compatibility review')
    if name in TOOLS:
        target = root / 'ansible/runner/tools.lock.json'
        lock = json.loads(target.read_text())
        prefix, template = TOOLS[name]
        url = prefix + template.format(version=version)
        raw = fetch(url, prefix=prefix)
        if name in ('tofu', 'op'):
            files = archive_files(raw)
            if name not in files:
                raise ValueError('Tool archive lacks its expected executable')
        else:
            import bz2
            binary = bz2.BZ2Decompressor().decompress(raw, max_length=128 * 1024 * 1024 + 1)
            if not binary or len(binary) > 128 * 1024 * 1024:
                raise ValueError('Restic binary is empty')
        old = json.loads(baseline(root, 'ansible/runner/tools.lock.json'))[name]['version']
        lock[name] = {'version': version, 'url': url, 'sha256': digest(raw)}
        if name == 'tofu':
            # Every native root/fixture declares the same runner OpenTofu version.
            versions = [p for parent in ('infra', 'ansible/playbooks')
                        for p in (root / parent).rglob('versions.tf') if '.terraform' not in p.parts]
            for path in versions:
                text = path.read_text()
                marker = 'required_version = "= ' + old + '"'
                replacement = 'required_version = "= ' + version + '"'
                if marker not in text and replacement not in text:
                    raise ValueError('OpenTofu companion constraint differs')
                path.write_text(text.replace(marker, replacement), newline='\n')
        write_json(target, lock)
        return {'owner': 'runner', 'changed': name, 'requiresBuild': ['candidate-runner']}
    if name == 'helm':
        target = root / 'ansible/runner/helm.lock.json'
        lock = json.loads(target.read_text())
        lock['version'] = 'v' + version
        hashes = {}
        for arch in ('amd64', 'arm64'):
            url = 'https://get.helm.sh/helm-v' + version + '-linux-' + arch + '.tar.gz'
            raw = fetch(url, prefix='https://get.helm.sh/')
            if 'linux-' + arch + '/helm' not in archive_files(raw):
                raise ValueError('Helm archive lacks its expected executable')
            hashes[arch] = digest(raw)
        lock['sha256'] = hashes
        write_json(target, lock)
        return {'owner': 'runner', 'changed': name, 'requiresBuild': ['candidate-runner']}
    target = root / 'ansible/playbooks/tailscale/files/release.json'
    url = 'https://pkgs.tailscale.com/stable/tailscale_' + version + '_amd64.tgz'
    raw = fetch(url, prefix='https://pkgs.tailscale.com/stable/')
    if not any(path.endswith('/tailscale') for path in archive_files(raw)):
        raise ValueError('Tailscale archive lacks its expected executable')
    write_json(target, {'version': version, 'url': url, 'sha256': digest(raw)})
    return {'owner': 'tailscale', 'changed': name, 'requiresBuild': []}


def gateway_plugin(root, version, *, fetch=download):
    import yaml
    relative = 'platform/delivery/rollouts/artifact.lock.json'
    original = json.loads(baseline(root, relative))['plugin']
    if (not re.fullmatch(r'[0-9]+[.][0-9]+[.][0-9]+', version) or
            version.split('.')[:2] != original['version'].lstrip('v').split('.')[:2]):
        raise ValueError('Gateway plugin minor changes require separate compatibility review')
    prefix = 'https://github.com/argoproj-labs/rollouts-plugin-trafficrouter-gatewayapi/releases/download/'
    url = prefix + 'v' + version + '/gatewayapi-plugin-linux-amd64'
    raw = fetch(url, prefix=prefix)
    if not raw.startswith(b'\x7fELF'):
        raise ValueError('Gateway plugin lacks its native Linux executable')
    target = owned_path(root, relative)
    lock = json.loads(target.read_bytes())
    lock['plugin'] = {'version': 'v' + version, 'url': url, 'sha256': digest(raw)}
    values_path = owned_path(root, 'platform/delivery/rollouts/values.yaml')
    values = yaml.safe_load(values_path.read_bytes())
    plugins = values['argo-rollouts']['controller']['trafficRouterPlugins']
    if len(plugins) != 1 or plugins[0]['name'] != 'argoproj-labs/gatewayAPI':
        raise ValueError('Gateway plugin owner differs from its reviewed traffic provider')
    plugins[0].update(location=url, sha256=digest(raw))
    values_path.write_text(yaml.safe_dump(values, sort_keys=False), newline='\n')
    write_json(target, lock)
    return {'owner': 'tool:gateway-api-plugin', 'status': 'pending-verification', 'pluginChecksumUpdated': True}


def debian(root, version, *, fetch=download):
    import datetime
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z', version):
        raise ValueError('Debian requires an exact UTC archive snapshot')
    datetime.datetime.strptime(version, '%Y%m%dT%H%M%SZ')
    path = owned_path(root, 'ansible/runner/debian.sources')
    original = baseline(root, 'ansible/runner/debian.sources').decode()
    dates = set(re.findall(r'https://snapshot[.]debian[.]org/archive/(?:debian|debian-security)/([0-9TZ]+)/', original))
    if len(dates) != 1:
        raise ValueError('Runner snapshot sources are inconsistent')
    for archive, suite in (('debian', 'bookworm'), ('debian-security', 'bookworm-security')):
        prefix = 'https://snapshot.debian.org/archive/' + archive + '/'
        raw = fetch(prefix + version + '/dists/' + suite + '/InRelease', prefix=prefix)
        if not raw.startswith(b'-----BEGIN PGP SIGNED MESSAGE-----'):
            raise ValueError('Debian snapshot lacks its signed release metadata')
    path.write_text(original.replace(next(iter(dates)), version), newline='\n')
    return {'owner': 'runner', 'status': 'pending-build', 'pendingBuild': 'candidate-runner',
            'next': 'docker compose -f ansible/playbooks/dependencies/compose.yaml build candidate-runner'}


def k3s(root, version, *, fetch=download):
    import yaml
    if not re.fullmatch(r'v?1\.[0-9]+\.[0-9]+\+k3s[0-9]+', version):
        raise ValueError('K3s requires an exact release version')
    version = 'v' + version.lstrip('v')
    target = owned_path(root, 'ansible/playbooks/k3s/vars.yml')
    lock = yaml.safe_load(target.read_bytes())
    original = yaml.safe_load(baseline(root, 'ansible/playbooks/k3s/vars.yml'))
    # A tested Kubernetes minor is the compatibility boundary, never a latest-major guess.
    if version.split('.')[1] != original['k3s_version'].split('.')[1]:
        raise ValueError('K3s minor updates require a separate compatibility review')
    prefix = 'https://github.com/k3s-io/k3s/releases/download/'
    release = prefix + urllib.parse.quote(version, safe='') + '/'
    binaries = {}
    for machine, arch, asset in (('x86_64', 'amd64', 'k3s'), ('aarch64', 'arm64', 'k3s-arm64')):
        manifest = fetch(release + 'sha256sum-' + arch + '.txt', prefix=prefix).decode()
        hashes = re.findall(r'^([a-f0-9]{64})\s+\*?' + re.escape(asset) + r'$', manifest, re.M)
        if len(hashes) != 1:
            raise ValueError('K3s checksum manifest lacks its exact binary')
        raw = fetch(release + asset, prefix=prefix)
        if not raw.startswith(b'\x7fELF') or digest(raw) != hashes[0]:
            raise ValueError('K3s binary checksum differs')
        binaries[machine] = {'asset': asset, 'sha256': hashes[0]}
    installer = fetch('https://raw.githubusercontent.com/k3s-io/k3s/' + urllib.parse.quote(version, safe='') + '/install.sh',
                      prefix='https://raw.githubusercontent.com/k3s-io/k3s/')
    if not installer.startswith(b'#!/bin/sh'):
        raise ValueError('K3s installer is not the expected shell artifact')
    from .ci_tools import image_digest
    from .images import apply
    proof = 'ansible/playbooks/keycloak/tests/compose.identity-operator-proof.yaml'
    current = yaml.safe_load(owned_path(root, proof).read_bytes())
    service = current['services']['cluster']
    old = service['image']
    if not old.startswith('rancher/k3s:'):
        raise ValueError('K3s proof image origin differs')
    updated = image_digest('rancher/k3s:' + version.replace('+', '-'))
    lock.update(k3s_version=version, k3s_installer_checksum='sha256:' + digest(installer), k3s_binaries=binaries)
    target.write_text(yaml.safe_dump(lock, sort_keys=False), newline='\n')
    apply(root, [proof, 'ansible/playbooks/dependencies/compose.yaml'], {old: updated})
    return {'owner': 'k3s', 'status': 'pending-verification', 'binaryArchitectures': sorted(binaries),
            'proofImageUpdated': True}


def finalize_helm(root):
    from .toolchain import embedded
    import subprocess
    import os
    embedded(root)
    result = subprocess.run(['helm', 'version', '--short'], capture_output=True, text=True, timeout=30,
                            env={'PATH': os.environ['PATH'], 'HOME': '/tmp/home'})
    version = result.stdout.strip()
    expected = json.loads(owned_path(root, 'ansible/runner/helm.lock.json').read_bytes())['version']
    if result.returncode or not version.startswith(expected + '+'):
        raise ValueError('Helm metadata requires the current built candidate Helm')
    changed = []
    owners = ('certificates/cert-manager', 'storage/longhorn', 'secrets/external-secrets', 'delivery/argocd',
              'connectivity/istio/base', 'connectivity/istio/istiod', 'connectivity/istio/cni', 'connectivity/istio/ztunnel')
    for owner in owners:
        path = owned_path(root, 'platform/' + owner + '/artifact.lock.json')
        lock = json.loads(path.read_bytes())
        if 'helm_version' not in lock:
            raise ValueError('Chart lacks its verified Helm metadata')
        lock['helm_version'] = expected.removeprefix('v') if owner == 'delivery/argocd' else version
        write_json(path, lock)
        changed.append(path.relative_to(root).as_posix())
    return {'owner': 'runner', 'status': 'pending-verification', 'helmVersion': version, 'metadataUpdated': changed}


def finalize_cosign(root):
    from .toolchain import embedded
    embedded(root)
    path = owned_path(root, 'platform/harbor/cosign.lock.json')
    lock = json.loads(path.read_bytes())
    original = json.loads(baseline(root, 'platform/harbor/cosign.lock.json'))
    version = cosign_version()
    if version.split('.')[:2] != original['version'].split('.')[:2]:
        raise ValueError('Cosign leaves its tested native CLI compatibility range')
    lock['version'] = version
    write_json(path, lock)
    return {'owner': 'image:cosign', 'status': 'pending-verification', 'nativeVersion': version}


def cosign_version():
    import os
    import subprocess
    result = subprocess.run(['cosign', 'version', '--json'], capture_output=True, text=True, timeout=30,
                            env={'PATH': os.environ['PATH'], 'HOME': '/tmp/home'})
    match = re.fullmatch(r'v([0-9]+[.][0-9]+[.][0-9]+)(?:[+][A-Za-z0-9._-]+)?',
                         json.loads(result.stdout)['gitVersion']) if not result.returncode else None
    if not match:
        raise ValueError('Cosign native version qualification failed')
    return match[1]


def check_cosign(root):
    lock = json.loads(owned_path(root, 'platform/harbor/cosign.lock.json').read_bytes())
    original = json.loads(baseline(root, 'platform/harbor/cosign.lock.json'))
    if (cosign_version() != lock['version'] or 'FROM ' + lock['image'] + ' AS cosign' not in
            owned_path(root, 'ansible/runner/Dockerfile').read_text() or
            lock['version'].split('.')[:2] != original['version'].split('.')[:2] or
            (lock['image'] != original['image'] and original['image'] not in lock['compatible_images'])):
        raise ValueError('Cosign native CLI or runner image companion differs from the owner lock')


OAUTH_LOCK = 'ansible/playbooks/harbor/tests/browser-proof.lock.json'
CERTIFICATES_LOCK = 'platform/certificates/cert-manager/artifact.lock.json'


def cmctl(root, version, *, fetch=download):
    original = json.loads(baseline(root, CERTIFICATES_LOCK))['renewal_tool']
    if (not re.fullmatch(r'[0-9]+[.][0-9]+[.][0-9]+', version) or
            version.split('.')[:2] != original['version'].split('.')[:2]):
        raise ValueError('Certificate tool minor changes require separate compatibility review')
    prefix = 'https://github.com/cert-manager/cmctl/releases/download/'
    url = prefix + 'v' + version + '/cmctl_linux_amd64'
    raw = fetch(url, prefix=prefix)
    pin = {'version': version, 'url': url, 'sha256': digest(raw)}
    check_cmctl(root, pin=pin, raw=raw)
    path = owned_path(root, CERTIFICATES_LOCK)
    lock = json.loads(path.read_bytes())
    lock['renewal_tool'] = pin
    write_json(path, lock)
    return {'owner': 'tool:cmctl', 'status': 'pending-verification', 'nativeVersionChecked': True}


def check_cmctl(root, *, pin=None, raw=None):
    import os
    import subprocess
    import tempfile
    pin = pin or json.loads(owned_path(root, CERTIFICATES_LOCK).read_bytes())['renewal_tool']
    prefix = 'https://github.com/cert-manager/cmctl/releases/download/'
    if (not re.fullmatch(r'[0-9]+[.][0-9]+[.][0-9]+', pin['version']) or
            pin['url'] != prefix + 'v' + pin['version'] + '/cmctl_linux_amd64'):
        raise ValueError('Certificate tool URL and version companions differ')
    raw = download(pin['url'], prefix=prefix, sha256=pin['sha256']) if raw is None else raw
    if digest(raw) != pin['sha256'] or not raw.startswith(b'\x7fELF'):
        raise ValueError('Certificate tool native bytes or checksum differ')
    with tempfile.TemporaryDirectory(prefix='maintenance-cmctl-') as temporary:
        executable = Path(temporary) / 'cmctl'
        executable.write_bytes(raw)
        executable.chmod(0o700)
        result = subprocess.run([str(executable), 'version', '--client'], capture_output=True, text=True, timeout=30,
                                env={'PATH': os.environ['PATH'], 'HOME': '/tmp/home', 'KUBECONFIG': '/dev/null'})
        if result.returncode or not re.search(r'(?<![A-Za-z0-9.])v?' + re.escape(pin['version']) + r'(?![A-Za-z0-9.])', result.stdout):
            raise ValueError('Certificate tool native version differs from its owner lock')


def oauth2_proxy(root, version, *, fetch=download):
    if not re.fullmatch(r'[0-9]+[.][0-9]+[.][0-9]+', version):
        raise ValueError('OAuth proxy requires an exact stable version')
    original = json.loads(baseline(root, OAUTH_LOCK))
    if version.split('.')[:2] != original['version'].split('.')[:2]:
        raise ValueError('OAuth proxy minor changes require separate compatibility review')
    prefix = 'https://github.com/oauth2-proxy/oauth2-proxy/releases/download/'
    url = prefix + 'v' + version + '/oauth2-proxy-v' + version + '.linux-amd64.tar.gz'
    raw = fetch(url, prefix=prefix)
    pin = {'version': version, 'url': url, 'sha256': digest(raw)}
    check_oauth2(root, pin=pin, raw=raw)
    write_json(owned_path(root, OAUTH_LOCK), pin)
    return {'owner': 'tool:oauth2-proxy', 'status': 'pending-verification', 'nativeVersionChecked': True}


def check_oauth2(root, *, pin=None, raw=None):
    import os
    import subprocess
    import tempfile
    pin = pin or json.loads(owned_path(root, OAUTH_LOCK).read_bytes())
    version = pin['version']
    prefix = 'https://github.com/oauth2-proxy/oauth2-proxy/releases/download/'
    expected = prefix + 'v' + version + '/oauth2-proxy-v' + version + '.linux-amd64.tar.gz'
    if not re.fullmatch(r'[0-9]+[.][0-9]+[.][0-9]+', version) or pin['url'] != expected:
        raise ValueError('OAuth proxy pin has inconsistent version and URL companions')
    raw = download(expected, prefix=prefix, sha256=pin['sha256']) if raw is None else raw
    if digest(raw) != pin['sha256']:
        raise ValueError('OAuth proxy archive checksum differs')
    binaries = [value for name, value in archive_files(raw).items() if name.rsplit('/', 1)[-1] == 'oauth2-proxy']
    if len(binaries) != 1 or not binaries[0].startswith(b'\x7fELF'):
        raise ValueError('OAuth proxy archive lacks its unique native executable')
    with tempfile.TemporaryDirectory(prefix='maintenance-oauth-') as temporary:
        executable = Path(temporary) / 'oauth2-proxy'
        executable.write_bytes(binaries[0])
        executable.chmod(0o700)
        result = subprocess.run([str(executable), '--version'], capture_output=True, text=True, timeout=30,
                                env={'PATH': os.environ['PATH'], 'HOME': '/tmp/home'})
        if result.returncode or not re.match(r'^oauth2-proxy v?' + re.escape(version) + r'(?:\s|$)', result.stdout):
            raise ValueError('OAuth proxy executable version differs from its source pin')
