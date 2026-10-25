"""Check completed pins against the original PR base before candidate code runs."""
import base64
import json
from pathlib import Path
import re

import yaml

from .security import owned_path


def minor(before, after):
    normalize = lambda value: str(value).removeprefix('gha-runner-scale-set-').lstrip('v').split('.')[:2]
    if normalize(before) != normalize(after):
        raise ValueError('Dependency leaves its reviewed minor compatibility range')


def origins(before, after, replacements=None):
    """Preserve complete approved URL paths, changing only explicit sibling pins."""
    replacements = dict(replacements or {})
    if isinstance(before, dict) and isinstance(after, dict):
        for key, value in before.items():
            if (isinstance(value, str) and isinstance(after.get(key), str) and
                    re.fullmatch(r'(?:(?:gha-runner-scale-set-)?v?[0-9]+[.][0-9]+(?:[.][0-9]+)?(?:[-+][A-Za-z0-9._+-]+)?|[a-f0-9]{40})', value)):
                replacements[value] = after[key]
        for key in before.keys() & after.keys():
            origins(before[key], after[key], replacements)
    elif isinstance(before, list) and isinstance(after, list):
        for left, right in zip(before, after):
            origins(left, right, replacements)
    elif isinstance(before, str) and before.startswith(('https://', 'oci://')):
        # Replace in one pass: new pins must not be replaced again by another pin.
        pattern = '|'.join(re.escape(value) for value in sorted(replacements, key=len, reverse=True))
        expected = re.sub(pattern, lambda match: replacements[match[0]], before) if pattern else before
        if after != expected:
            raise ValueError('Dependency URL leaves its exact approved source path')


def verify(root, plan):
    root = Path(root)
    from .images import provenance
    provenance(root, plan, resolve=None)
    versions, python_versions = {}, {}
    for path, encoded in plan['baseFiles'].items():
        target = owned_path(root, path)
        if not target.is_file():
            continue
        old, new = base64.b64decode(encoded, validate=True), target.read_bytes()
        if old == new:
            continue
        if path.endswith(('requirements.txt', 'telemetry-requirements.txt')):
            from .requirements import parse
            before, after = parse(old), parse(new)
            if set(before) != set(after):
                raise ValueError('Python package inventory changed')
            for name in before:
                minor(before[name]['version'], after[name]['version'])
                if before[name]['version'] != after[name]['version']:
                    if name in python_versions and python_versions[name] != after[name]['version']:
                        raise ValueError('Python maintenance must use one compatible version across owners')
                    python_versions[name] = after[name]['version']
        elif path.endswith('/versions.tf'):
            pattern = r'\b(required_version|version)\s*=\s*"=\s*([^"]+)"'
            before, after = re.findall(pattern, old.decode()), re.findall(pattern, new.decode())
            if len(before) != len(after):
                raise ValueError('Native constraint inventory changed')
            for (name, left), (other, right) in zip(before, after):
                if name != other:
                    raise ValueError('Native constraint owner changed')
                minor(left, right)
        elif path.endswith('/.terraform.lock.hcl'):
            pattern = r'provider\s+"([^"]+)"\s*\{\s*version\s*=\s*"([^"]+)"'
            before, after = dict(re.findall(pattern, old.decode())), dict(re.findall(pattern, new.decode()))
            if set(before) != set(after):
                raise ValueError('Native provider lock inventory changed')
            for name in before:
                minor(before[name], after[name])
        elif path == 'ansible/runner/debian.sources':
            import datetime
            dates = set(re.findall(r'/([0-9]{8}T[0-9]{6}Z)/', new.decode()))
            if len(dates) != 1:
                raise ValueError('Debian sources require one reviewed snapshot cohort')
            datetime.datetime.strptime(dates.pop(), '%Y%m%dT%H%M%SZ')
        elif path == 'ansible/playbooks/k3s/vars.yml':
            minor(yaml.safe_load(old)['k3s_version'], yaml.safe_load(new)['k3s_version'])
        elif path.endswith('.json'):
            before, after = json.loads(old), json.loads(new)
            if path == 'platform/connectivity/tailscale-operator/artifact.lock.json':
                url = after.get('upstream_url')
                release = re.fullmatch(r'https://pkgs[.]tailscale[.]com/helmcharts/tailscale-operator-'
                                       r'([0-9]+[.][0-9]+[.][0-9]+)-[0-9]{10}-([a-f0-9]{64})[.]tgz', url) if isinstance(url, str) else None
                if not release or release.groups() != (after['version'], after['upstream_sha256']):
                    raise ValueError('Tailscale chart URL differs from its fixed release family and checksum')
                # The official index binds the changing timestamp/hash in mandatory chart provenance.
                origins({key: value for key, value in before.items() if key != 'upstream_url'},
                        {key: value for key, value in after.items() if key != 'upstream_url'})
            else:
                origins(before, after)
            if path == 'ansible/runner/tools.lock.json':
                for name in ('tofu', 'op', 'restic'):
                    minor(before[name]['version'], after[name]['version'])
            elif path.endswith(('/cloudflare-provider.lock.json', '/harbor-provider.lock.json')):
                minor(before['version'], after['version'])
                def parse(value):
                    match = re.fullmatch(r'([0-9]+)[.]([0-9]+)[.]([0-9]+)-cloudlab[.]([0-9]+)', value)
                    if not match:
                        raise ValueError('Invalid derivative provider version')
                    return tuple(map(int, match.groups()))
                if parse(after['version']) < parse(before['version']) or after['patch_sha256'] != before['patch_sha256']:
                    raise ValueError('Derivative provider version or reviewed patch changed incompatibly')
                if after['version'] == before['version'] and any(after[field] != before[field] for field in ('source', 'go', 'patch_sha256', 'package_sha256')):
                    raise ValueError('Changed provider content requires a new immutable derivative version')
                minor(before['go']['version'], after['go']['version'])
            elif path == 'platform/delivery/ci/tools/source.lock.json':
                for left, right in zip(before['sources'], after['sources']):
                    if left['name'] != right['name']:
                        raise ValueError('CI source owner changed')
                    minor(left['version'], right['version'])
            elif path == 'platform/delivery/ci/runner/source.lock.json':
                if after['runner_version'].split('.')[0] != before['runner_version'].split('.')[0]:
                    raise ValueError('CI runner leaves its reviewed major')
                versions[before['runner_version']] = after['runner_version']
                minor(before['runtime_version'], after['runtime_version'])
                for name in before['security_packages']:
                    minor(before['security_packages'][name], after['security_packages'][name])
            elif path == 'platform/identity/keycloak/artifact.lock.json':
                for field in ('operator_version', 'server_version', 'config_cli_version', 'config_cli_build_server'):
                    minor(before[field], after[field])
            elif path == 'ansible/playbooks/keycloak/tests/browser/package-lock.json':
                from .browser import validate_lock
                validate_lock(old, new)
            elif path == 'ansible/playbooks/keycloak/tests/browser/package.json':
                from .browser import validate_package
                validate_package(old, new)
            elif path.endswith('/artifact.lock.json'):
                left = before['chart'] if isinstance(before.get('chart'), dict) else before
                right = after['chart'] if isinstance(after.get('chart'), dict) else after
                field = 'version' if 'version' in left else 'chart'
                if field in left:
                    minor(left[field], right[field])
                for field in ('plugin', 'renewal_tool'):
                    if field in before:
                        minor(before[field]['version'], after[field]['version'])
            elif path.endswith(('/helm.lock.json', '/release.json', '/image.lock.json', '/browser-proof.lock.json', '/cosign.lock.json')):
                minor(before['version'], after['version'])
    if python_versions:
        from .requirements import FILES, parse
        for path in FILES:
            if path not in plan['baseFiles']:
                raise ValueError('Python maintenance requires its complete existing owner group')
            for name, value in parse(owned_path(root, path).read_bytes()).items():
                if name in python_versions and value['version'] != python_versions[name]:
                    raise ValueError('Python maintenance omitted a coupled requirement companion')
    # Literal source/linker versions may not bypass their lock's compatibility rules.
    for path, encoded in plan['baseFiles'].items():
        if not (path.endswith('Dockerfile') or path.endswith('/runner.patch')):
            continue
        target = owned_path(root, path)
        if not target.is_file():
            continue
        before, after = base64.b64decode(encoded, validate=True).decode().splitlines(), target.read_text().splitlines()
        for left, right in zip(before, after):
            if left == right or left.startswith('FROM '):
                continue
            pattern = r'(?<![0-9.])v?([0-9]+[.][0-9]+[.][0-9]+)'
            old_versions, new_versions = re.findall(pattern, left), re.findall(pattern, right)
            if len(old_versions) != len(new_versions):
                raise ValueError('Native build version companions changed shape')
            for old, new in zip(old_versions, new_versions):
                if versions.get(old) != new:
                    minor(old, new)
