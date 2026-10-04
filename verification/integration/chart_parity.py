"""Offline, fail-closed semantic review of inactive chart migration candidates.

This does not install charts, filter an apply stream, or transfer ownership.
Only documented representation/packaging differences are normalized.
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tarfile

import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[2]
MODULES = [('secrets/external-secrets', 'external_secrets'), ('storage/longhorn', 'longhorn')]


def identity(item):
    return (item['apiVersion'], item['kind'],
            item['metadata'].get('namespace', ''), item['metadata']['name'])


def index(items):
    result = {}
    for item in items:
        key = identity(item)
        if key in result:
            raise ValueError(f'Duplicate object: {key}')
        result[key] = item
    return result


def normalize(item, module):
    item = copy.deepcopy(item)
    if module == 'external_secrets' and item['kind'] == 'CustomResourceDefinition':
        annotations = item['metadata'].get('annotations', {})
        option = annotations.pop('argocd.argoproj.io/sync-options', None)
        if option not in (None, 'ServerSideApply=true,Prune=false,Delete=false'):
            raise ValueError('Unreviewed ESO CRD ownership options')
    if module == 'longhorn':
        # These two labels do not participate in existing selectors.
        for metadata in (item['metadata'], item.get('spec', {}).get('template', {}).get('metadata', {})):
            labels = metadata.get('labels', {})
            for key, expected in [('app.kubernetes.io/managed-by', 'Helm'), ('helm.sh/chart', 'longhorn-1.13.0')]:
                if key in labels:
                    if labels[key] != expected:
                        raise ValueError(f'Unexpected packaging label: {key}')
                    del labels[key]
    if item['kind'] == 'ConfigMap' and item['metadata']['name'] in ('longhorn-default-setting', 'longhorn-storageclass'):
        for key, value in item['data'].items():
            parsed = yaml.safe_load(value)
            if key == 'default-setting.yaml':
                parsed = {k: str(v).lower() if isinstance(v, bool) else v for k, v in parsed.items()}
            item['data'][key] = parsed
    return item


def differences(a, b, path=''):
    if a == b:
        return []
    if isinstance(a, dict) and isinstance(b, dict):
        return [p for key in sorted(a.keys() | b.keys())
                for p in differences(a.get(key), b.get(key), path + '/' + key)]
    return [path]


def container_images(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in ('containers', 'initContainers', 'ephemeralContainers'):
                for container in child:
                    yield container['image']
            else:
                yield from container_images(child)
    elif isinstance(value, list):
        for child in value:
            yield from container_images(child)


def verify(module, old):
    folder = ROOT / 'platform' / module
    lock = json.loads((folder / 'artifact.lock.json').read_text())
    archive = folder / lock.get('archive', 'upstream.tgz')
    if hashlib.sha256(archive.read_bytes()).hexdigest() != lock['sha256']:
        raise ValueError(f'{module}: chart checksum mismatch')
    for relative, expected in lock['baseline_inputs'].items():
        # Git normalizes text line endings; a Windows checkout must match Linux.
        if hashlib.sha256((ROOT / relative).read_text(encoding='utf-8').encode()).hexdigest() != expected:
            raise ValueError(f'{module}: baseline changed; review {relative}')
    if subprocess.check_output(['helm', 'version', '--short'], text=True).strip() != lock['helm_version']:
        raise ValueError('Use the locked Compose Helm renderer')
    with tarfile.open(archive) as package:
        chart = yaml.safe_load(package.extractfile(lock['release_name'] + '/Chart.yaml'))
        schema = any(x.name == lock['release_name'] + '/values.schema.json' for x in package)
    if chart['version'] != lock['version']:
        raise ValueError('Chart version differs from lock')
    chart_path = folder if (folder / 'Chart.yaml').exists() else archive
    subprocess.run(['helm', 'lint', str(chart_path), '--strict', '--kube-version', lock['kube_version'],
                    '-f', str(folder / 'values.json')], check=True, capture_output=True)
    command = ['helm', 'template', lock['release_name'], str(chart_path), '--namespace', lock['namespace'],
               '--kube-version', lock['kube_version'], '--include-crds', '-f', str(folder / 'values.json')]
    rendered = subprocess.check_output(command)
    if rendered != subprocess.check_output(command):
        raise ValueError('Chart render is nondeterministic')
    candidate = list(filter(None, yaml.safe_load_all(rendered)))
    if old == 'external_secrets':
        stores = [x for x in candidate if x['kind'] == 'ClusterSecretStore']
        if stores:
            settings = json.loads((folder / 'values.json').read_text())['cloudlab']
            environment = Environment(undefined=StrictUndefined)
            environment.filters['to_json'] = json.dumps
            environment.filters['hash'] = lambda value, algorithm: hashlib.new(algorithm, value.encode()).hexdigest()
            template = (ROOT / 'ansible/roles/external_secrets/templates/store.yml.j2').read_text()
            expected = yaml.safe_load(environment.from_string(template).render(
                external_secrets_store=settings['store'], external_secrets_vault=settings['vault'],
                external_secrets_token='non-secret-parity-fixture'))
            # Bootstrap retains only the token-change notification annotation.
            expected['metadata'].pop('annotations')
            if stores != [expected]:
                raise ValueError('ESO store spec differs from its existing bootstrap declaration')
            candidate = [x for x in candidate if x['kind'] != 'ClusterSecretStore']
    if (folder / 'config.yaml').exists():
        candidate += list(filter(None, yaml.safe_load_all((folder / 'config.yaml').read_text())))
    # The chart has no off switches for these hooks. Report them, never apply them.
    hooks = [x for x in candidate if 'helm.sh/hook' in x['metadata'].get('annotations', {})]
    expected_hooks = {'longhorn-post-upgrade': 'post-upgrade', 'longhorn-uninstall': 'pre-delete'} if old == 'longhorn' else {}
    if {x['metadata']['name']: x['metadata']['annotations']['helm.sh/hook'] for x in hooks} != expected_hooks:
        raise ValueError('Unexpected chart hook inventory')
    allowed_images = {tag + '@' + digest for tag, digest in lock['images'].items()}
    if not set(container_images(candidate)) <= allowed_images:
        raise ValueError(f'{module}: unexpected or unpinned container image')
    image_refs = set(re.findall(r'(?:docker.io/longhornio/|ghcr.io/external-secrets/)[a-zA-Z0-9_./:@-]+', json.dumps(candidate)))
    if image_refs != allowed_images:
        raise ValueError(f'{module}: runtime image set differs from lock')
    spec = importlib.util.spec_from_file_location(old, ROOT / 'automation' / old / 'render.py')
    baseline_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline_module)
    groups = baseline_module.render()
    baseline = index([normalize(x, old) for items in groups.values() for x in items])
    actual = index([normalize(x, old) for x in candidate if x not in hooks])
    if baseline.keys() != actual.keys():
        raise ValueError(f'{module}: object identity changed')
    changed = {str(key): differences(baseline[key], actual[key])
               for key in baseline if baseline[key] != actual[key]}
    if changed:
        raise ValueError(f'{module}: unreviewed semantic changes: {changed}')
    canonical = json.dumps(
        [actual[k] for k in sorted(actual)], sort_keys=True, separators=(',', ':'))
    return dict(module=module, objects=len(actual), crds=sum(k[1] == 'CustomResourceDefinition' for k in actual),
                images=len(image_refs), chart_sha256=lock['sha256'],
                semantic_sha256=hashlib.sha256(canonical.encode()).hexdigest(),
                chart_schema_present=schema, lint='passed', deterministic=True,
                unexplained_differences=0, excluded_hooks=expected_hooks,
                adoption_ready=False)


if __name__ == '__main__':
    print(json.dumps([verify(*module) for module in MODULES], indent=2))
