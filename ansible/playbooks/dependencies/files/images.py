"""Maintain image tags, digests and the owning generated values together."""
import json
import os
from pathlib import Path
import re
import subprocess
import base64

import yaml

from .ci_tools import image_digest
from .inventory import ROOT, selected
from .security import owned_path
from .tools import write_json
from .validate import file_change

PIN = re.compile(r'[A-Za-z0-9][A-Za-z0-9./:_-]+@sha256:[a-f0-9]{64}')


def compatible_tag(before, after):
    if before is None:
        return False
    pattern = r'v?([0-9]+)[.]([0-9]+)(?:[.][0-9]+)?(.*)'
    old, new = re.fullmatch(pattern, before), re.fullmatch(pattern, after)
    if not old or not new or old.groups()[:2] != new.groups()[:2]:
        return False
    normalize = lambda value: re.sub(r'-k3s[0-9]+$', '-k3s<build>', value)
    return normalize(old[3]) == normalize(new[3])


def reference(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9./:_-]+@sha256:[a-f0-9]{64}', value):
        raise ValueError('Image owner requires an immutable image reference')
    name, sha256 = value.split('@')
    last = name.rsplit('/', 1)[-1]
    repository, tag = name.rsplit(':', 1) if ':' in last else (name, None)
    registry = repository.split('/')[0]
    if ('.' in registry or ':' in registry) and registry not in {
            'docker.io', 'ghcr.io', 'quay.io', 'cgr.dev', 'mcr.microsoft.com',
            'registry.k8s.io', 'reg.kyverno.io'}:
        raise ValueError('Image owner requires a designated public registry')
    return repository, tag, sha256


def compatible_postgresql(before, after):
    # PostgreSQL 10+ uses major.patch, with the selected distribution fixed.
    old = re.fullmatch(r'([0-9]+)[.][0-9]+(-standard-trixie)', before or '')
    new = re.fullmatch(r'([0-9]+)[.][0-9]+(-standard-trixie)', after or '')
    return bool(old and new and old.groups() == new.groups())


def transform(value, replacements):
    if isinstance(value, str):
        for old, new in replacements.items():
            if old in value:
                value = value.replace(old, new)
            repository, tag, sha256 = reference(old)
            _, updated, new_sha256 = reference(new)
            value = value.replace(repository + '@' + sha256, repository + '@' + new_sha256)
            if tag is not None and value == tag + '@' + sha256:
                return updated + '@' + new_sha256
        return value
    if isinstance(value, list):
        return [transform(item, replacements) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        for old, new in replacements.items():
            old_name, old_sha = old.split('@')
            new_name, new_sha = new.split('@')
            if key == old_name and item == old_sha:
                key, item = new_name, new_sha
                break
        result[key] = transform(item, replacements)
    for old, new in replacements.items():
        repository, tag, sha256 = reference(old)
        _, updated, new_sha256 = reference(new)
        candidates = [value.get('repository'), value.get('image')]
        normalize = lambda name: name.removeprefix('docker.io/').removeprefix('library/')
        if any(isinstance(item, str) and normalize(item) == normalize(repository) for item in candidates):
            if value.get('tag') == tag:
                result['tag'] = updated
            if value.get('digest') == sha256:
                result['digest'] = new_sha256
    return result


def apply(root, paths, replacements):
    changed = []
    for relative in sorted(set(paths)):
        path = owned_path(root, relative)
        if not path.is_file():
            continue
        before = path.read_bytes()
        if path.suffix == '.json':
            value = json.loads(before)
            updated = transform(value, replacements)
            if updated != value:
                write_json(path, updated)
        elif path.suffix in ('.yaml', '.yml') and 'templates' not in path.parts:
            value = yaml.safe_load(before)
            updated = transform(value, replacements)
            if updated != value:
                path.write_text(yaml.safe_dump(updated, sort_keys=False), newline='\n')
        elif path.name == 'Dockerfile' or path.suffix == '.py':
            text = before.decode()
            for old, new in replacements.items():
                text = text.replace(old, new)
            if text != before.decode():
                path.write_text(text, newline='\n')
        if path.read_bytes() != before:
            changed.append(relative)
    return changed


def packages(root, name):
    environment = {'PATH': os.environ['PATH'], 'HOME': '/tmp/home', 'PYTHONDONTWRITEBYTECODE': '1',
                   'PYTHONPATH': str(Path(root) / 'ansible') + ':' + str(root)}
    if name in {'istio', 'python'}:
        source = Path(root) / 'platform/connectivity/istio/images.lock.json'
        if name == 'istio':
            (Path(root) / 'ansible/playbooks/previews/files/images.lock.json').write_bytes(source.read_bytes())
        module = 'playbooks.previews.files.package'
    elif name in {'observability', 'harbor'}:
        module = 'playbooks.' + name + '.files.package'
    else:
        return
    result = subprocess.run(['python', '-m', module, 'build'], cwd=root, env=environment,
                            capture_output=True, timeout=120)
    if result.returncode:
        raise ValueError('Existing image owner packaging failed')


def update(root, name, request):
    if set(request) != {'selector', 'version'} or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,100}', request['version']):
        raise ValueError('Image updates require an explicit image selector and complete public tag')
    if name.startswith('pin:'):
        return proof(root, name, request)
    owner = selected(['image:' + name])['image:' + name]
    relative = owner['sources'][0]
    path = owned_path(root, relative)
    trusted_raw = (ROOT / relative).read_bytes()
    file_change(relative, trusted_raw, path.read_bytes())
    lock = json.loads(path.read_text())
    values = lock.get('images', lock)
    selector = request['selector']
    if selector not in owner['selectors']:
        raise ValueError('Image selector is not owned by this image group')
    key = selector_key(values, selector)
    old = key + '@' + values[key] if values[key].startswith('sha256:') else values[key]
    repository, tag, _ = reference(old)
    previous = json.loads(trusted_raw)
    previous = previous.get('images', previous)
    previous_key = selector_key(previous, selector)
    approved = previous_key + '@' + previous[previous_key] if previous[previous_key].startswith('sha256:') else previous[previous_key]
    _, approved_tag, _ = reference(approved)
    channel = owner.get('digestChannel')
    compatible = compatible_postgresql(approved_tag, request['version']) if name == 'postgresql' else compatible_tag(approved_tag, request['version'])
    if not ((approved_tag is None or approved_tag == channel) and request['version'] == channel) and not compatible:
        raise ValueError('Image tag leaves its tested version or distribution range')
    chosen = {old}
    # These upstream releases ship their matching components as one version.
    if name in {'istio', 'harbor', 'admission', 'access', 'certificates'}:
        namespace = repository.rsplit('/', 1)[0] + '/'
        for candidate, value in values.items():
            current = candidate + '@' + value if value.startswith('sha256:') else value
            origin, current_tag, _ = reference(current)
            if origin.startswith(namespace):
                chosen.add(current)
    if name == 'observability' and key in {'operator', 'reloader'}:
        chosen = {values['operator'], values['reloader']}
    replacements = {value: image_digest(reference(value)[0] + ':' + request['version']) for value in sorted(chosen)}
    previous = json.loads(trusted_raw)
    previous = previous.get('images', previous)
    for key, value in previous.items():
        if not isinstance(value, str):
            continue
        original = key + '@' + value if value.startswith('sha256:') else value
        if '@sha256:' not in original:
            continue
        origin, _, _ = reference(original)
        for current, updated in list(replacements.items()):
            if reference(current)[0] == origin:
                replacements[original] = updated
    changed = apply(root, owner['writePaths'], replacements)
    if name == 'cosign':
        from .inputs import baseline
        original = json.loads(baseline(root, relative))
        updated = json.loads(path.read_bytes())
        if updated['image'] != original['image'] and original['image'] not in updated['compatible_images']:
            updated['compatible_images'].append(original['image'])
        write_json(path, updated)
    if name == 'maintenance':
        updated = json.loads(path.read_bytes())
        updated['version'] = request['version']
        write_json(path, updated)
    packages(root, name)
    return {'owner': 'image:' + name, 'status': 'pending-verification', 'images': len(replacements),
            'unchanged': not bool(changed),
            'pendingBuild': ['candidate-runner', 'candidate-ci-controller', 'candidate-ci-builder', 'candidate-ci-runner'] if name in {'ci-runner', 'ci-scan'} else
                            'candidate-runner' if any(path.endswith('Dockerfile') for path in changed) else None}


def proof(root, name, request):
    owner = selected([name])[name]
    if owner['updater'] != 'image' or not owner.get('selectors'):
        raise ValueError('This pin has a separate owner; it is not a standalone proof image')
    source = owner['sources'][0]
    old_source = (ROOT / source).read_bytes()
    current = owned_path(root, source).read_bytes()
    file_change(source, old_source, current)
    selector = request['selector']
    if selector not in owner['selectors']:
        raise ValueError('Unsupported proof image selector')
    refs = set(PIN.findall(current.decode()))
    chosen = [value for value in refs if reference(value)[0] == selector]
    if len(chosen) != 1:
        raise ValueError('Proof image requires one unambiguous owned public origin')
    if not compatible_tag(reference(chosen[0])[1], request['version']):
        raise ValueError('Proof image tag leaves its tested version or distribution range')
    target = image_digest(selector + ':' + request['version'])
    replacements = {chosen[0]: target}
    replacements.update({value: target for value in PIN.findall(old_source.decode()) if reference(value)[0] == selector})
    changed = apply(root, owner['writePaths'], replacements)
    if not changed and chosen[0] != target:
        raise ValueError('Proof image companion update is incomplete')
    return {'owner': name, 'status': 'pending-verification', 'image': target, 'changedFiles': changed}


def selector_key(values, selector):
    if selector in values and isinstance(values[selector], str):
        return selector
    # Native regex updates can rename a tag-key before repairing its digest.
    repository, _, _ = reference(selector + '@sha256:' + '0' * 64)
    matches = [key for key, value in values.items() if isinstance(value, str) and value.startswith('sha256:') and
               reference(key + '@' + value)[0] == repository]
    if len(matches) != 1:
        raise ValueError('Image selector is absent or ambiguous after its native tag update')
    return matches[0]


def references(value, *, include_tagless=False):
    """Read full pins and the existing repository/tag/digest companion forms."""
    found = set()
    def collect(item):
        if isinstance(item, str):
            found.update(pin.split(':-')[-1] for pin in PIN.findall(item))
        elif isinstance(item, list):
            for child in item:
                collect(child)
        elif isinstance(item, dict):
            for key, child in item.items():
                if isinstance(key, str) and isinstance(child, str) and re.fullmatch(r'sha256:[a-f0-9]{64}', child):
                    found.add(key + '@' + child)
                collect(child)
            repository = item.get('repository') or item.get('image')
            tag, sha = item.get('tag'), item.get('digest')
            if isinstance(repository, str) and isinstance(tag, str):
                if '@sha256:' in tag:
                    found.add(repository + ':' + tag)
                elif isinstance(sha, str):
                    found.add(repository + ':' + tag + '@' + sha)
    collect(value)
    result = set()
    for pin in found:
        try:
            repository, tag, sha = reference(pin)
        except ValueError:
            continue
        if tag is None and '/' not in repository and repository not in {'python', 'golang', 'alpine', 'redis', 'postgres', 'busybox'}:
            continue
        if tag is not None or include_tagless:
            result.add((repository, tag, sha))
    return result


def provenance(root, plan, *, resolve=image_digest):
    """Verify repaired changed tags without running candidate code or using credentials."""
    def pins(raw, path):
        if raw is None:
            return set()
        text = raw.decode()
        if path.endswith('.json'):
            value = json.loads(text)
            if path == 'platform/harbor/cosign.lock.json':
                value.pop('compatible_images', None)
            return references(value, include_tagless=True)
        if path.endswith(('.yaml', '.yml')) or path.endswith('Chart.lock'):
            return references(list(yaml.safe_load_all(text)), include_tagless=True)
        return references(text, include_tagless=True)

    changed, removed, active = set(), set(), set()
    for path, encoded in plan['baseFiles'].items():
        if not (path.endswith(('.json', '.yaml', '.yml', '.py', '.Dockerfile')) or path.endswith('Dockerfile')):
            continue
        target = owned_path(root, path)
        if not target.is_file():
            continue
        before, after = base64.b64decode(encoded, validate=True), target.read_bytes()
        current = pins(after, path)
        active.update(current)
        if before != after:
            previous = pins(before, path)
            removed.update(previous - current)
            if path == 'platform/observability/images.lock.json':
                values = json.loads(after)
                if reference(values['operator'])[1] != reference(values['reloader'])[1]:
                    raise ValueError('Coupled monitoring operator and reloader versions differ')
            if path in {'platform/connectivity/istio/images.lock.json', 'platform/harbor/images.lock.json',
                        'platform/delivery/admission/artifact.lock.json', 'platform/connectivity/access/images.lock.json',
                        'platform/certificates/cert-manager/artifact.lock.json'}:
                for namespace in {origin.rsplit('/', 1)[0] + '/' for origin, _, _ in previous}:
                    group = {(origin, tag) for origin, tag, _ in previous if origin.startswith(namespace)}
                    if len(group) > 1 and len({tag for _, tag in group}) == 1:
                        if len({tag for origin, tag, _ in current if origin.startswith(namespace)}) != 1:
                            raise ValueError('Coupled image components must retain one reviewed release version')
            for repository, tag, sha in current - previous:
                old_tags = [old for origin, old, _ in previous if origin == repository]
                def compatible(old):
                    if old == tag:
                        return True
                    if old is None or tag is None:
                        return old is None and tag == 'latest' and repository == 'cgr.dev/chainguard/cosign'
                    if repository == 'ghcr.io/cloudnative-pg/postgresql':
                        return compatible_postgresql(old, tag)
                    if repository == 'ghcr.io/actions/actions-runner':
                        return old.split('.')[0] == tag.split('.')[0] == '2'
                    if repository == 'quay.io/adorsys/keycloak-config-cli':
                        pairs = [re.fullmatch(r'([0-9]+[.][0-9]+)[.][0-9]+-([0-9]+[.][0-9]+)[.][0-9]+', value) for value in (old, tag)]
                        return all(pairs) and pairs[0].groups() == pairs[1].groups()
                    return compatible_tag(old, tag)
                if not old_tags or not any(compatible(old) for old in old_tags):
                    raise ValueError('Changed image leaves its immutable-base compatibility range')
                if tag is not None:
                    changed.add((repository, tag, sha))
    if removed & active:
        raise ValueError('Image maintenance omitted an active immutable companion copy')
    if resolve is None:
        return len(changed)
    resolved = {}
    for repository, tag, sha in sorted(changed):
        reference_tag = repository + ':' + tag
        if reference_tag not in resolved:
            resolved[reference_tag] = {resolve(reference_tag).rsplit('@', 1)[1]}
        if sha not in resolved[reference_tag]:
            resolved[reference_tag].add(resolve(reference_tag, platform='linux/amd64').rsplit('@', 1)[1])
        if sha not in resolved[reference_tag]:
            raise ValueError('Changed image digest differs from its exact official tag')
    return len(changed)
