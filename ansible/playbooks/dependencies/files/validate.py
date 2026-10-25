"""Keep dependency changes from becoming executable-code or configuration changes."""
import json
from pathlib import PurePosixPath
import re
import urllib.parse

import yaml

from .security import public_url

VERSION = re.compile(r'v?[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9._+-]+)?')
HEX = re.compile(r'(?:sha256:)?[a-f0-9]{64}')
IMAGE = re.compile(r'([A-Za-z0-9./_-]+)(?::([A-Za-z0-9._-]+))?@sha256:[a-f0-9]{64}')


def normalized_url(value):
    public_url(value)
    parsed = urllib.parse.urlsplit(value)
    if parsed.hostname in {'github.com', 'codeload.github.com', 'raw.githubusercontent.com'}:
        prefix = '/'.join(parsed.path.split('/')[:3])
    else:
        prefix = ''
    value = re.sub(r'(?<![A-Za-z0-9])[a-f0-9]{40,64}(?![A-Za-z0-9])', '<hash>', value)
    return prefix, re.sub(r'v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._+-]+)?', '<version>', value)


def scalar(old, new):
    if old == new:
        return True
    if not isinstance(old, str) or not isinstance(new, str):
        return False
    if VERSION.fullmatch(old) and VERSION.fullmatch(new):
        return True
    if all(re.fullmatch(r'gha-runner-scale-set-[0-9]+[.][0-9]+[.][0-9]+', value) for value in (old, new)):
        return True
    if HEX.fullmatch(old) and HEX.fullmatch(new):
        return True
    if re.fullmatch(r'[a-f0-9]{40}', old) and re.fullmatch(r'[a-f0-9]{40}', new):
        return True
    if re.fullmatch(r'actions/checkout@[a-f0-9]{40}', old) and re.fullmatch(r'actions/checkout@[a-f0-9]{40}', new):
        return True
    old_image, new_image = IMAGE.fullmatch(old), IMAGE.fullmatch(new)
    if old_image and new_image:
        return old_image[1] == new_image[1]
    old_images, new_images = list(IMAGE.finditer(old)), list(IMAGE.finditer(new))
    if (old_images and len(old_images) == len(new_images) and
            all(a[1] == b[1] for a, b in zip(old_images, new_images)) and
            IMAGE.sub('<image>', old) == IMAGE.sub('<image>', new)):
        return True
    if old.startswith('https://') and new.startswith('https://'):
        return normalized_url(old) == normalized_url(new)
    # Archive paths and Helm image tag/digest values have no executable grammar.
    if '@sha256:' in old and '@sha256:' in new:
        before, after = old.split('@sha256:'), new.split('@sha256:')
        return (len(before) == len(after) == 2 and VERSION.fullmatch(before[0]) is not None and
                VERSION.fullmatch(after[0]) is not None and HEX.fullmatch(before[1]) is not None and
                HEX.fullmatch(after[1]) is not None)
    if old.endswith(('.tgz', '.zip')) and new.endswith(('.tgz', '.zip')):
        return re.sub(r'v?\d+\.\d+\.\d+', '<version>', old) == re.sub(r'v?\d+\.\d+\.\d+', '<version>', new)
    return False


def structured(old, new):
    if isinstance(old, dict) and isinstance(new, dict):
        if set(old) != set(new):
            # A map keyed by full image tags may rename only that tag, never its origin.
            removed, added = set(old) - set(new), set(new) - set(old)
            if not removed and added == {'commit'} and re.fullmatch(r'[a-f0-9]{40}', str(new['commit'])):
                added = set()
            if len(removed) != len(added):
                return False
            for key in removed:
                repository, separator, version = key.rpartition(':')
                matches = [other for other in added if other.rpartition(':')[0] == repository]
                if (not separator or not VERSION.fullmatch(version) or len(matches) != 1 or
                        not VERSION.fullmatch(matches[0].rpartition(':')[2]) or
                        not HEX.fullmatch(str(old[key])) or not HEX.fullmatch(str(new[matches[0]]))):
                    return False
        for key in set(old) & set(new):
            if key in {'semantic_sha256', 'migration_baseline_revision'} and old[key] != new[key]:
                return False
            if key == 'contentHash' and all(re.fullmatch(r'[A-Za-z0-9+/]{86}==', str(value)) for value in (old[key], new[key])):
                continue
            if not structured(old[key], new[key]):
                return False
        return True
    if isinstance(old, list) and isinstance(new, list):
        return len(old) == len(new) and all(structured(before, after) for before, after in zip(old, new))
    return scalar(old, new)


def dockerfile(old, new):
    before, after = old.splitlines(), new.splitlines()
    if len(before) != len(after):
        return False
    for left, right in zip(before, after):
        if left == right:
            continue
        if left.startswith('FROM ') and right.startswith('FROM '):
            tokens, changed = left.split(), right.split()
            if tokens[2:] != changed[2:] or not scalar(tokens[1], changed[1]):
                return False
        else:
            # Existing checksum, source version and linker version tokens may change;
            # no new instruction, shell grammar, command or argument may appear.
            def normalize(line):
                line = re.sub(r'(?<![A-Za-z0-9])[a-f0-9]{40,64}(?![A-Za-z0-9])', '<hash>', line)
                return re.sub(r'v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._+-]+)?', '<version>', line)
            old_urls = re.findall(r'https://[^\s\x22\x27\\]+', left)
            new_urls = re.findall(r'https://[^\s\x22\x27\\]+', right)
            if len(old_urls) != len(new_urls) or any(normalized_url(a) != normalized_url(b)
                                                    for a, b in zip(old_urls, new_urls)):
                return False
            if normalize(left) != normalize(right):
                return False
    return True


def file_change(path, old, new):
    """Reject helper/test edits and non-pin fields before running candidate code."""
    name = PurePosixPath(path).name
    if old == new:
        return
    if name.endswith(('.tgz', '.zip')) or name in {'upstream.yaml'}:
        # Existing owner checks must reproduce these bytes from their locked source.
        return
    if old is None or new is None:
        raise ValueError('Maintenance cannot add or remove executable or configuration inputs')
    before, after = old.decode(), new.decode()
    if path in {'platform/delivery/services/sigstore-fulcio.crt', 'ansible/playbooks/previews/files/sigstore-fulcio.crt',
                'platform/delivery/previews/runtime/sigstore-fulcio.crt'}:
        from .trust import validate
        validate(old, new)
        return
    if path.startswith('platform/identity/keycloak/upstream/') and name in {
            'kubernetes.yml', 'keycloaks.k8s.keycloak.org-v1.yml', 'keycloakrealmimports.k8s.keycloak.org-v1.yml'}:
        if not all(isinstance(row, dict) and row.get('apiVersion') and row.get('kind')
                   for row in yaml.safe_load_all(after) if row):
            raise ValueError('Malformed official identity raw artifacts')
        return
    if path == 'ansible/playbooks/buildkit/files/buildkit-seccomp.json':
        from .profiles import seccomp
        seccomp(old, new)
        return
    if path == 'ansible/playbooks/buildkit/files/cloudlab-buildkit':
        from .profiles import apparmor
        apparmor(old, new)
        return
    if name == 'profiles.lock.json':
        original, updated = json.loads(before), json.loads(after)
        sources = updated.pop('reviewed_sources', {})
        original.pop('reviewed_sources', None)
        if set(sources) != {'seccomp', 'apparmor'} or any(
                set(value) != {'url', 'sha256'} or not re.fullmatch(r'[a-f0-9]{64}', value['sha256']) or
                not re.fullmatch(r'https://raw[.]githubusercontent[.]com/containerd/containerd/[a-f0-9]{40}/contrib/(?:seccomp/seccomp_default[.]go|apparmor/template[.]go)', value['url'])
                for value in sources.values()):
            raise ValueError('Profile source review metadata is invalid')
        valid = structured(original, updated)
    elif name == 'Dockerfile' or name.endswith('.Dockerfile'):
        valid = dockerfile(before, after)
    elif name.endswith('.json'):
        if path.startswith('platform/delivery/ci/runner/nuget/') and name == 'packages.lock.json':
            from .nuget import validate_lock
            validate_lock(old, new)
            return
        if path == 'ansible/playbooks/keycloak/tests/browser/package-lock.json':
            from .browser import validate_lock
            validate_lock(old, new)
            return
        if path == 'ansible/playbooks/keycloak/tests/browser/package.json':
            from .browser import validate_package
            validate_package(old, new)
            return
        original, updated = json.loads(before), json.loads(after)
        if path == 'platform/harbor/cosign.lock.json':
            previous = original['compatible_images']
            if updated['compatible_images'] not in (previous, previous + [original['image']]):
                raise ValueError('Cosign maintenance must preserve exact historical verifier images')
            original['compatible_images'] = updated['compatible_images']
        if path == 'platform/identity/keycloak/artifact.lock.json':
            if type(updated.get('operator_install_verified')) is not bool:
                raise ValueError('Identity qualification flag must remain boolean')
            # The trusted isolated-proof recorder owns readiness, never this flag alone.
            original['operator_install_verified'] = updated['operator_install_verified']
        valid = structured(original, updated)
        if name in ('cloudflare-provider.lock.json', 'harbor-provider.lock.json'):
            changed = any(original[key] != updated[key] for key in
                          ('source', 'go', 'patch_sha256', 'package_sha256'))
            if changed and original['version'] == updated['version']:
                valid = False
    elif name.endswith(('.yaml', '.yml')) or name == 'Chart.lock':
        valid = structured(yaml.safe_load(before), yaml.safe_load(after))
    elif name == 'versions.tf':
        def normalize(text):
            return re.sub(r'((?:required_version|version)\s*=\s*"=\s*)' + VERSION.pattern + '(")',
                          r'\1<version>\2', text)
        valid = normalize(before) == normalize(after)
    elif name == '.terraform.lock.hcl':
        def normalize(text):
            text = re.sub(r'(?m)^\s*"(?:h1:[A-Za-z0-9+/=]+|zh:[a-f0-9]{64})",?\s*$', '', text)
            text = re.sub(r'(\b(?:version|constraints)\s*=\s*")[^"]+("\s*)', r'\1<version>\2', text)
            return re.sub(r'\s+', ' ', text)
        valid = normalize(before) == normalize(after)
    elif name in ('go.mod', 'go.sum'):
        if name == 'go.sum':
            valid = all(re.fullmatch(r'[A-Za-z0-9._~+/-]+ v[^\s]+ h1:[A-Za-z0-9+/=]+', line)
                        for line in after.splitlines() if line.strip())
        else:
            valid = (re.findall(r'^module .+$', before, re.M) == re.findall(r'^module .+$', after, re.M) and
                     re.findall(r'^replace .+$', before, re.M) == re.findall(r'^replace .+$', after, re.M))
            for line in after.splitlines():
                line = line.split('//', 1)[0].strip()
                if not line or line == ')' or line.startswith(('module ', 'replace ')):
                    continue
                if (line in ('require (', 'replace (') or re.fullmatch(r'(?:go [0-9.]+|toolchain go[0-9.]+)', line) or
                        re.fullmatch(r'(?:require )?[A-Za-z0-9._~+/-]+ v[^\s]+', line)):
                    continue
                valid = False
                break
    elif name in {'requirements.txt', 'telemetry-requirements.txt'}:
        from .requirements import parse
        valid = set(parse(old)) == set(parse(new))
    elif name == 'debian.sources':
        normalize = lambda text: re.sub(r'(https://snapshot[.]debian[.]org/archive/(?:debian|debian-security)/)[0-9]{8}T[0-9]{6}Z/',
                                        r'\1<snapshot>/', text)
        valid = normalize(before) == normalize(after)
    elif path == 'platform/delivery/ci/runner/runner.patch':
        pattern = r'(?m)^(\+[^\n]*<PackageReference Include="System[.](?:Security[.]Cryptography[.]Pkcs|Formats[.]Asn1)" Version=")[^"]+("[^\n]*)$'
        valid = re.sub(pattern, r'\1<version>\2', before) == re.sub(pattern, r'\1<version>\2', after)
    elif name.endswith('.py') and not name.startswith('test_'):
        before_lines, after_lines = before.splitlines(), after.splitlines()
        valid = len(before_lines) == len(after_lines)
        for left, right in zip(before_lines, after_lines):
            if left == right:
                continue
            old_images, new_images = list(IMAGE.finditer(left)), list(IMAGE.finditer(right))
            if (not old_images or len(old_images) != len(new_images) or
                    any(a[1] != b[1] for a, b in zip(old_images, new_images)) or
                    IMAGE.sub('<image>', left) != IMAGE.sub('<image>', right)):
                valid = False
                break
    else:
        valid = False
    if not valid:
        raise ValueError('Maintenance changed code, protected fields or an unsupported pin format: ' + path)
