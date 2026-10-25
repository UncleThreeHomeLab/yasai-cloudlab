"""Update chart artifacts through their existing deterministic owner patchers."""
import copy
import base64
import json
from pathlib import Path
import re
import tempfile
import urllib.parse

import yaml

from . import images
from .inventory import ROOT, selected
from .native import command
from .security import archive_files, digest, download, owned_path
from .tools import write_json
from .inputs import baseline


def entry(lock):
    return lock['chart'] if isinstance(lock.get('chart'), dict) else lock


def dependencies_hash(required, locked):
    # Helm v4 resolver.HashReq marshals Dependency fields in this declared order.
    fields = ('name', 'version', 'repository', 'condition', 'tags', 'enabled', 'import-values', 'alias')
    def encode(rows):
        return [{key: row.get(key, '') for key in fields
                 if key in {'name', 'repository'} or row.get(key)} for row in rows]
    return 'sha256:' + digest(json.dumps([encode(required), encode(locked)], separators=(',', ':'), ensure_ascii=False).encode())


def patch(name, raw):
    archive_files(raw)
    if name == 'storage/longhorn':
        from playbooks.longhorn.files.vendor_chart import package
        return package(raw)
    if name == 'certificates/cert-manager':
        from playbooks.certificates.files.vendor_chart import patched
        return patched(raw)
    if name == 'connectivity/tailscale-operator':
        from playbooks.access.files.vendor_operator import patched
        return patched(raw)
    if name == 'data/cnpg':
        from playbooks.data.files.vendor_cnpg import patched
        return patched(raw, expected_sha256=digest(raw))
    if name == 'harbor/server':
        from playbooks.harbor.files.package import patched
        return patched(raw)
    if name.startswith('observability/'):
        from playbooks.observability.files.package import retained, kiali_declarative, tempo_protocols
        patcher = {'prometheus': retained, 'kiali': kiali_declarative, 'tempo': tempo_protocols}.get(name.rsplit('/', 1)[1])
        if patcher:
            return patcher(raw)
    return raw


def upstream(lock, dependency, version, *, fetch=download):
    pin = entry(lock)
    old_version = str(pin.get('version', pin.get('chart', '')))
    url = pin.get('url') or lock.get('upstream_url')
    if not url:
        raise ValueError('Chart owner lacks its explicit upstream artifact URL')
    if url.startswith('oci://'):
        if not url.startswith('oci://ghcr.io/actions/actions-runner-controller-charts/'):
            raise ValueError('Unsupported chart OCI origin')
        temporary = Path(tempfile.mkdtemp(prefix='maintenance-chart-'))
        command(['helm', 'pull', url, '--version', version, '--destination', str(temporary)], cwd=temporary)
        archives = list(temporary.glob('*.tgz'))
        if len(archives) != 1:
            raise ValueError('Chart OCI artifact inventory differs')
        return archives[0].read_bytes(), url
    if 'upstream_url' in lock:
        index_url = 'https://pkgs.tailscale.com/helmcharts/index.yaml'
        index = yaml.safe_load(fetch(index_url, prefix='https://pkgs.tailscale.com/helmcharts/'))
        rows = [row for row in index['entries'][dependency['name']] if str(row['version']).lstrip('v') == version.lstrip('v')]
        if len(rows) != 1 or len(rows[0]['urls']) != 1:
            raise ValueError('Tailscale chart version is absent or ambiguous')
        target = urllib.parse.urljoin('https://pkgs.tailscale.com/helmcharts/', rows[0]['urls'][0])
        raw = fetch(target, prefix='https://pkgs.tailscale.com/helmcharts/', sha256=rows[0].get('digest'))
        return raw, target
    if not old_version or old_version not in url:
        raise ValueError('Chart URL is not derived from its pinned version')
    if old_version.startswith('v') and not version.startswith('v'):
        version = 'v' + version
    target = url.replace(old_version, version)
    parsed = urllib.parse.urlsplit(url)
    prefix = parsed.scheme + '://' + parsed.netloc + ('/'.join(parsed.path.split('/')[:3]) + '/' if parsed.hostname == 'github.com' else '/')
    return fetch(target, prefix=prefix), target


def one(root, name, version, *, fetch=download):
    owner = selected(['chart:' + name])['chart:' + name]
    source = owner['sources'][0]
    directory = Path(root) / Path(source).parent
    lock_path = directory / 'artifact.lock.json'
    lock = json.loads(lock_path.read_text())
    original = entry(json.loads(baseline(root, source)))
    approved_version = str(original.get('version', original.get('chart', ''))).lstrip('v')
    if version.lstrip('v').split('.')[:2] != approved_version.split('.')[:2]:
        raise ValueError('Chart minor changes require separate compatibility review')
    pin = entry(lock)
    if 'archive' not in pin:
        raise ValueError('Requested owner is not a vendored chart')
    old_archive = owned_path(directory, pin['archive'])
    old_metadata_files = archive_files(old_archive.read_bytes())
    old_roots = [value for path, value in old_metadata_files.items() if path.count('/') == 1 and path.endswith('/Chart.yaml')]
    if len(old_roots) != 1:
        raise ValueError('Owned chart archive has an ambiguous root')
    old_metadata = yaml.safe_load(old_roots[0])
    wrapper_path = directory / 'Chart.yaml'
    wrapper = yaml.safe_load(wrapper_path.read_text())
    if len(wrapper.get('dependencies', [])) != 1:
        raise ValueError('Chart owner requires exactly its declared upstream dependency')
    dependency = wrapper['dependencies'][0]
    if dependency['name'] != old_metadata['name']:
        raise ValueError('Chart dependency differs from its owned archive')
    if 'source_release_url' in lock:
        version = version.lstrip('v')
        from playbooks.istio.files.vendor_charts import from_release, patched
        approved_lock = json.loads(baseline(root, source))
        target = approved_lock['source_release_url'].replace(approved_lock['version'], version)
        release = fetch(target, prefix='https://github.com/istio/istio/releases/download/')
        raw = from_release(release, name.rsplit('/', 1)[1], version=version, sha256=digest(release))
        data = patched(raw, name.rsplit('/', 1)[1])
        lock.update(source_release_url=target, source_release_sha256=digest(release))
    else:
        raw, target = upstream(json.loads(baseline(root, source)), dependency, version, fetch=fetch)
        data = patch(name, raw)
        if 'upstream_url' in lock:
            lock['upstream_url'] = target
        else:
            pin['url'] = target
    metadata_files = archive_files(raw)
    roots = [value for path, value in metadata_files.items() if path.count('/') == 1 and path.endswith('/Chart.yaml')]
    if len(roots) != 1:
        raise ValueError('Downloaded chart archive has an ambiguous root')
    metadata = yaml.safe_load(roots[0])
    if metadata['name'] != dependency['name'] or str(metadata['version']).lstrip('v') != version.lstrip('v'):
        raise ValueError('Downloaded chart metadata differs from the requested owner/version')
    version = str(metadata['version'])
    old_version = str(old_metadata['version'])
    filename = 'charts/' + dependency['name'] + '-' + version + '.tgz'
    new_archive = owned_path(directory, filename)
    if old_archive != new_archive and new_archive.exists():
        raise ValueError('New chart archive path already exists')
    lock_file = directory / 'Chart.lock'
    updated_lock = None
    if lock_file.exists():
        updated_lock = yaml.safe_load(lock_file.read_text())
        original_required = copy.deepcopy(wrapper['dependencies'])
        original_required[0]['version'] = updated_lock['dependencies'][0]['version']
        if dependencies_hash(original_required, updated_lock['dependencies']) != updated_lock['digest']:
            raise ValueError('Existing Helm dependency lock digest differs')
        updated_lock['dependencies'][0]['version'] = version
    dependency['version'] = version
    if updated_lock:
        updated_lock['digest'] = dependencies_hash(wrapper['dependencies'], updated_lock['dependencies'])
    version_key = 'version' if 'version' in pin else 'chart'
    pin[version_key], pin['archive'], pin['sha256'] = version, filename, digest(data)
    for key in ('appVersion', 'app_version'):
        if key in pin:
            pin[key] = str(metadata['appVersion'])
    if 'upstream_sha256' in lock:
        lock['upstream_sha256'] = digest(raw)
        (directory / 'upstream.tgz').write_bytes(raw)
    if wrapper.get('appVersion', '').lstrip('v') == str(old_metadata.get('appVersion', '')).lstrip('v'):
        wrapper['appVersion'] = str(metadata['appVersion']).lstrip('v')
    new_archive.parent.mkdir(parents=True, exist_ok=True)
    new_archive.write_bytes(data)
    write_json(lock_path, lock)
    wrapper_path.write_text(yaml.safe_dump(wrapper, sort_keys=False), newline='\n')
    if updated_lock:
        lock_file.write_text(yaml.safe_dump(updated_lock, sort_keys=False), newline='\n')
    if old_archive != new_archive:
        old_archive.unlink()
    return owner, old_metadata, metadata


def update(root, name, version, *, fetch=download):
    if not re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('Chart maintenance requires an explicit stable version')
    version = version.lstrip('v')
    if name in {'delivery/ci/controller', 'delivery/ci/pool'}:
        from .ci_tools import update as update_tool
        return update_tool(root, 'arc', version.lstrip('v'))
    names = ['connectivity/istio/' + component for component in ('base', 'istiod', 'cni', 'ztunnel')] if name.startswith('connectivity/istio/') else [name]
    replacements, outputs = {}, set()
    owner_inputs = selected(['chart:' + name])
    outputs.update(path for owner in owner_inputs.values() for path in owner['writePaths'])
    metadata_after = None
    for target in names:
        owner, before, after = one(root, target, version, fetch=fetch)
        metadata_after = after
        outputs.update(owner['writePaths'])
        source = Path(root) / owner['sources'][0]
        lock = json.loads(source.read_text())
        pins = lock.get('images', {})
        if 'image' in lock:
            pins = dict(pins, image=lock['image'])
        for key, value in pins.items():
            old = key + '@' + value if value.startswith('sha256:') else value
            repository, tag, _ = images.reference(old)
            if tag is not None and tag.lstrip('v') == str(before.get('appVersion', '')).lstrip('v'):
                new_tag = ('v' if tag.startswith('v') else '') + str(after['appVersion']).lstrip('v')
                replacements[old] = images.image_digest(repository + ':' + new_tag)
    if replacements:
        images.apply(root, outputs, replacements)
    related = None
    selector = None
    if name.startswith('connectivity/istio/'):
        related, selector = 'istio', 'pilot'
    elif name == 'harbor/server':
        related, selector = 'harbor', 'harbor-core'
    elif name.startswith('observability/'):
        related, selector = 'observability', {'prometheus': 'operator', 'loki': 'loki', 'tempo': 'tempo',
                                             'alloy': 'alloy', 'kiali': 'kiali'}[name.rsplit('/', 1)[1]]
    elif name == 'delivery/admission':
        related, selector = 'admission', 'kyverno'
    elif name == 'connectivity/tailscale-operator':
        related, selector = 'access', 'ingress'
    if related:
        pins = json.loads((Path(root) / owner_inputs['image:' + related]['sources'][0]).read_text())
        pins = pins.get('images', pins)
        old = pins[selector]
        _, tag, _ = images.reference(old)
        target_tag = ('v' if tag and tag.startswith('v') else '') + str(metadata_after['appVersion']).lstrip('v')
        # Tailscale's digest-only operator pin still needs its coupled image repair.
        if tag != target_tag or name == 'connectivity/tailscale-operator':
            images.update(root, related, {'selector': selector, 'version': target_tag})
    return {'owner': 'chart:' + name, 'status': 'pending-verification', 'chartsUpdated': len(names),
            'archiveLocksUpdated': True, 'requiredChecks': sorted(set(check for target in names for check in selected(['chart:' + target])['chart:' + target]['checks']))}


def provenance(root, plan, *, fetch=download):
    """Reproduce changed artifacts from immutable-base origins before Helm sees them."""
    root, downloads = Path(root), {}
    def cached(url, **arguments):
        if url not in downloads:
            downloads[url] = fetch(url, **arguments)
        raw = downloads[url]
        if arguments.get('sha256') and digest(raw) != arguments['sha256']:
            raise ValueError('Official chart download checksum differs')
        return raw

    for source, encoded in plan['baseFiles'].items():
        if not source.startswith('platform/') or not source.endswith('/artifact.lock.json'):
            continue
        original = json.loads(base64.b64decode(encoded, validate=True))
        approved = entry(original)
        if 'archive' not in approved:
            continue
        lock = json.loads(owned_path(root, source).read_bytes())
        pin = entry(lock)
        name = str(Path(source).parent).replace('\\', '/').removeprefix('platform/')
        directory = root / Path(source).parent
        version = str(pin.get('version', pin.get('chart', '')))
        old_version = str(approved.get('version', approved.get('chart', '')))
        from .compatibility import minor
        minor(old_version, version)
        filename = Path(approved['archive']).name
        suffix = '-' + old_version + '.tgz'
        if not filename.endswith(suffix):
            raise ValueError('Approved chart archive does not match its locked version')
        chart_name = filename[:-len(suffix)]
        expected_archive = 'charts/' + chart_name + '-' + version + '.tgz'
        if pin['archive'] != expected_archive or {path.name for path in (directory / 'charts').glob('*.tgz')} != {Path(expected_archive).name}:
            raise ValueError('Chart dependency archive inventory differs from its exact owner')
        data = owned_path(directory, pin['archive']).read_bytes()
        if digest(data) != pin['sha256']:
            raise ValueError('Chart artifact checksum differs from candidate bytes')
        wrapper = yaml.safe_load((directory / 'Chart.yaml').read_bytes())
        dependencies = wrapper.get('dependencies', [])
        if len(dependencies) != 1 or dependencies[0]['name'] != chart_name or str(dependencies[0]['version']) != version:
            raise ValueError('Wrapper differs from its exact chart dependency')
        wrapper_path = str(Path(source).parent / 'Chart.yaml').replace('\\', '/')
        if wrapper_path in plan['baseFiles']:
            previous_wrapper = yaml.safe_load(base64.b64decode(plan['baseFiles'][wrapper_path], validate=True))
            before = copy.deepcopy(previous_wrapper['dependencies'])
            before[0]['version'] = version
            if before != dependencies:
                raise ValueError('Chart dependency origin or options changed')
        native_lock = directory / 'Chart.lock'
        if native_lock.is_file():
            native = yaml.safe_load(native_lock.read_bytes())
            identity = lambda rows: [{key: row[key] for key in ('name', 'version', 'repository')} for row in rows]
            if identity(native['dependencies']) != identity(dependencies) or native['digest'] != dependencies_hash(dependencies, native['dependencies']):
                raise ValueError('Native Helm dependency lock differs')
        if 'upstream_sha256' in original and digest((directory / 'upstream.tgz').read_bytes()) != lock['upstream_sha256']:
            raise ValueError('Raw chart bytes differ from their locked checksum')
        # A digest bound to the approved base already authenticates unchanged bytes.
        if (version == old_version and pin == approved and data and
                all(lock.get(field) == original.get(field) for field in ('upstream_url', 'upstream_sha256', 'source_release_url', 'source_release_sha256'))):
            continue
        if 'source_release_url' in original:
            target = original['source_release_url'].replace(old_version, version)
            if lock['source_release_url'] != target:
                raise ValueError('Istio release origin differs from the approved base')
            release = cached(target, prefix='https://github.com/istio/istio/releases/download/')
            if digest(release) != lock['source_release_sha256']:
                raise ValueError('Istio release checksum differs from official bytes')
            from playbooks.istio.files.vendor_charts import from_release, patched
            component = name.rsplit('/', 1)[1]
            raw = from_release(release, component, version=version, sha256=digest(release))
            expected = patched(raw, component)
        else:
            raw, target = upstream(original, {'name': chart_name}, version, fetch=cached)
            if (lock.get('upstream_url') if 'upstream_url' in original else pin.get('url')) != target:
                raise ValueError('Chart URL differs from its exact approved release path')
            expected = patch(name, raw)
        if data != expected:
            raise ValueError('Vendored chart differs from its official deterministic artifact')
        if 'upstream_sha256' in original and (lock['upstream_sha256'] != digest(raw) or
                (directory / 'upstream.tgz').read_bytes() != raw):
            raise ValueError('Raw chart archive differs from its exact official artifact')
        metadata = [yaml.safe_load(value) for path, value in archive_files(raw).items()
                    if path.count('/') == 1 and path.endswith('/Chart.yaml')]
        if len(metadata) != 1 or metadata[0]['name'] != chart_name or str(metadata[0]['version']) != version:
            raise ValueError('Official chart metadata differs from its lock')
        for field in ('appVersion', 'app_version'):
            if field in pin and str(pin[field]) != str(metadata[0]['appVersion']):
                raise ValueError('Chart application version differs from official metadata')
