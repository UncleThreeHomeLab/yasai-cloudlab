"""Update the reviewed Playwright package graph and matching browser image together."""
import base64
import copy
import hashlib
import json
import re

from .ci_tools import image_digest
from .security import archive_files, download, owned_path
from .tools import write_json
from .inputs import baseline

BASE = 'ansible/playbooks/keycloak/tests/browser/'
PACKAGES = ('playwright', 'playwright-core')
REGISTRY = 'https://registry.npmjs.org/'
VERSION = re.compile(r'[0-9]+[.][0-9]+[.][0-9]+')


def version(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ValueError('Browser maintenance requires an exact stable version')
    return value


def compatible(before, after):
    if version(before).split('.')[:2] != version(after).split('.')[:2]:
        raise ValueError('Browser version-line changes require separate compatibility review')


def integrity(value):
    if not isinstance(value, str) or not value.startswith('sha512-'):
        raise ValueError('Browser packages require exact SHA512 integrity')
    try:
        raw = base64.b64decode(value[7:], validate=True)
    except ValueError:
        raise ValueError('Invalid browser package integrity') from None
    if len(raw) != 64 or base64.b64encode(raw).decode() != value[7:]:
        raise ValueError('Invalid browser package integrity')
    return raw


def tarball(name, current):
    return REGISTRY + name + '/-/' + name + '-' + version(current) + '.tgz'


def validate_package(old, new):
    before, after = json.loads(old), json.loads(new)
    if before.get('private') is not True or after.get('private') is not True:
        raise ValueError('Browser proof package must remain private')
    for document in (before, after):
        if set(document.get('dependencies', {})) != {'playwright'}:
            raise ValueError('Browser proof requires only its reviewed direct dependency')
    compatible(before['dependencies']['playwright'], after['dependencies']['playwright'])
    before['dependencies']['playwright'] = after['dependencies']['playwright']
    if before != after:
        raise ValueError('Browser maintenance changed package identity or commands')


def lock(document):
    if (document.get('lockfileVersion') != 3 or document.get('requires') is not True or
            set(document.get('packages', {})) != {'', 'node_modules/playwright', 'node_modules/playwright-core'}):
        raise ValueError('Browser maintenance requires the reviewed two-package native lock')
    root = document['packages']['']
    if (set(root.get('dependencies', {})) != {'playwright'} or root.get('name') != document.get('name') or
            root.get('version') != document.get('version')):
        raise ValueError('Browser lock root identity differs')
    current = version(root['dependencies']['playwright'])
    for name in PACKAGES:
        entry = document['packages']['node_modules/' + name]
        expected_dependencies = {'playwright-core': current} if name == 'playwright' else {}
        if (entry.get('version') != current or entry.get('resolved') != tarball(name, current) or
                entry.get('dependencies', {}) != expected_dependencies or
                set(entry) - {'version', 'resolved', 'integrity', 'license', 'dependencies', 'bin', 'engines'}):
            raise ValueError('Browser lock package origin or dependency graph differs')
        integrity(entry.get('integrity'))
    return current


def validate_lock(old, new):
    before, after = json.loads(old), json.loads(new)
    original, current = lock(before), lock(after)
    compatible(original, current)
    before['packages']['']['dependencies']['playwright'] = current
    for name in PACKAGES:
        entry, updated = (document['packages']['node_modules/' + name] for document in (before, after))
        if original == current and entry['integrity'] != updated['integrity']:
            raise ValueError('An unchanged npm version cannot acquire replacement package bytes')
        for key in ('version', 'resolved', 'integrity'):
            entry[key] = updated[key]
        if name == 'playwright':
            entry['dependencies']['playwright-core'] = current
    if before != after:
        raise ValueError('Browser maintenance changed protected native lock fields')


def package(name, current, previous, fetch):
    metadata = json.loads(fetch(REGISTRY + name + '/' + current, prefix=REGISTRY + name + '/'))
    if metadata.get('name') != name or metadata.get('version') != current:
        raise ValueError('Official browser package identity differs')
    dependencies = {'playwright-core': current} if name == 'playwright' else {}
    if (metadata.get('dependencies', {}) != dependencies or
            any(metadata.get(key) for key in ('optionalDependencies', 'peerDependencies', 'bundledDependencies', 'bundleDependencies')) or
            any(metadata.get(key) != previous.get(key) for key in ('license', 'bin', 'engines'))):
        raise ValueError('Browser package graph or compatibility fields require separate review')
    distribution = metadata['dist']
    if distribution.get('tarball') != tarball(name, current):
        raise ValueError('Browser package tarball differs from the official registry origin')
    expected = integrity(distribution.get('integrity'))
    raw = fetch(distribution['tarball'], prefix=REGISTRY + name + '/-/')
    if hashlib.sha512(raw).digest() != expected:
        raise ValueError('Browser package checksum mismatch')
    manifest = json.loads(archive_files(raw)['package/package.json'])
    if (manifest.get('name') != name or manifest.get('version') != current or
            manifest.get('dependencies', {}) != dependencies or
            any(manifest.get(key) for key in ('optionalDependencies', 'peerDependencies', 'bundledDependencies', 'bundleDependencies')) or
            any(manifest.get(key) != metadata.get(key) for key in ('license', 'bin', 'engines'))):
        raise ValueError('Browser package archive differs from verified registry metadata')
    updated = dict(previous, version=current, resolved=distribution['tarball'], integrity=distribution['integrity'])
    if name == 'playwright':
        updated['dependencies'] = dependencies
    return updated


def update(root, request, *, fetch=download, resolve=image_digest):
    if set(request) != {'version'}:
        raise ValueError('Browser maintenance requires one exact version')
    current = version(request['version'])
    paths = {name: owned_path(root, BASE + name) for name in ('package.json', 'package-lock.json', 'Dockerfile')}
    old = {name: baseline(root, BASE + name) for name in paths}
    document = json.loads(old['package.json'])
    original = version(document['dependencies']['playwright'])
    compatible(original, current)
    locked = json.loads(old['package-lock.json'])
    if lock(locked) != original:
        raise ValueError('Browser package and native lock versions differ')
    updated = copy.deepcopy(locked)
    updated['packages']['']['dependencies']['playwright'] = current
    for name in PACKAGES:
        key = 'node_modules/' + name
        updated['packages'][key] = package(name, current, locked['packages'][key], fetch)
    document['dependencies']['playwright'] = current
    validate_package(old['package.json'], json.dumps(document).encode())
    validate_lock(old['package-lock.json'], json.dumps(updated).encode())
    dockerfile = old['Dockerfile'].decode().replace('\r\n', '\n')
    pattern = r'\AFROM mcr[.]microsoft[.]com/playwright:v' + re.escape(original) + r'-noble@sha256:[a-f0-9]{64}\n'
    if (not re.match(pattern, dockerfile) or
            'RUN npm ci --ignore-scripts --registry=https://registry.npmjs.org\n' not in dockerfile):
        raise ValueError('Browser build must preserve its approved image and script-free native install')
    reference = 'mcr.microsoft.com/playwright:v' + current + '-noble'
    image = resolve(reference)
    if not re.fullmatch(re.escape(reference) + r'@sha256:[a-f0-9]{64}', image):
        raise ValueError('Resolved browser image differs from its matching official version')
    dockerfile = re.sub(pattern, 'FROM ' + image + '\n', dockerfile, count=1)
    write_json(paths['package.json'], document)
    write_json(paths['package-lock.json'], updated)
    paths['Dockerfile'].write_text(dockerfile, newline='\n')
    return {'owner': 'identity-browser', 'status': 'pending-build', 'pendingBuild': 'identity-browser',
            'version': current, 'nativeInstall': 'npm ci --ignore-scripts'}
