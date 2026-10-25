"""Refresh existing Python packages across compatible hash-locked wheel inputs."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from .security import download, owned_path
from .inputs import baseline

FILES = ('ansible/runner/requirements.txt', 'apps/notes/requirements.txt',
         'apps/notes/telemetry-requirements.txt', 'ansible/playbooks/observability/tests/requirements.txt')
VERSION = r'[0-9]+(?:[.][0-9]+)*(?:(?:a|b|rc|post|dev)[0-9]+)?'


def normalized(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def parse(raw):
    result = {}
    for line in raw.decode().replace('\r\n', '\n').replace('\\\n', ' ').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*([A-Za-z0-9][A-Za-z0-9._-]*)==(' + VERSION +
                             r')((?:\s+--hash=sha256:[a-f0-9]{64})+)\s*', line)
        if not match or normalized(match[1]) in result:
            raise ValueError('Requirements permit only exact existing packages and SHA256 hashes')
        result[normalized(match[1])] = {'name': match[1], 'version': match[2],
                                      'hashes': re.findall(r'sha256:([a-f0-9]{64})', match[3])}
    if not result:
        raise ValueError('Requirements must not be empty')
    return result


def update(root, request, *, fetch=download):
    if set(request) != {'versions'} or not isinstance(request['versions'], dict) or not request['versions']:
        raise ValueError('Python maintenance requires explicit existing package versions')
    documents = {name: parse(owned_path(root, name).read_bytes()) for name in FILES}
    originals = {name: parse(baseline(root, name)) for name in FILES}
    names = set().union(*(set(document) for document in documents.values()))
    chosen = {}
    for name, version in request['versions'].items():
        if name != normalized(name) or name not in names or not isinstance(version, str) or not re.fullmatch(VERSION, version):
            raise ValueError('Unsupported Python package or version')
        if any(version.split('.')[:2] != document[name]['version'].split('.')[:2]
               for document in originals.values() if name in document):
            raise ValueError('Python package minor changes require separate compatibility review')
        metadata = json.loads(fetch('https://pypi.org/pypi/' + name + '/' + version + '/json', prefix='https://pypi.org/pypi/'))
        if normalized(metadata['info']['name']) != name or metadata['info']['version'] != version:
            raise ValueError('Public Python release identity differs')
        hashes = sorted({row['digests']['sha256'] for row in metadata['urls']
                         if row['packagetype'] == 'bdist_wheel' and not row.get('yanked')})
        if not hashes or any(not re.fullmatch(r'[a-f0-9]{64}', value) for value in hashes):
            raise ValueError('Python release lacks its checksum-locked wheels')
        chosen[name] = version, hashes
    outputs = {}
    for relative, document in documents.items():
        for name, (version, hashes) in chosen.items():
            if name in document:
                document[name].update(version=version, hashes=hashes)
        raw = '# Locked wheels for Python 3.13 on Linux amd64.\n' + ''.join(
            row['name'] + '==' + row['version'] + ''.join(' --hash=sha256:' + value for value in row['hashes']) + '\n'
            for row in document.values())
        parse(raw.encode())
        outputs[relative] = raw
    with tempfile.TemporaryDirectory(prefix='maintenance-wheels-') as temporary:
        for index, (relative, raw) in enumerate(outputs.items()):
            lock = Path(temporary) / (str(index) + '.txt')
            lock.write_text(raw)
            result = subprocess.run([sys.executable, '-m', 'pip', '--isolated', 'download', '--disable-pip-version-check',
                '--no-cache-dir', '--only-binary=:all:', '--require-hashes', '--index-url', 'https://pypi.org/simple',
                '--dest', str(Path(temporary) / str(index)), '-r', str(lock)],
                env={'PATH': os.environ['PATH'], 'HOME': '/tmp/home'}, capture_output=True, timeout=600)
            if result.returncode:
                raise ValueError('Python wheel hashes or compatible complete dependency closure failed')
    for relative, raw in outputs.items():
        owned_path(root, relative).write_text(raw, newline='\n')
    return {'owner': 'python-requirements', 'status': 'pending-build', 'pendingBuild': 'candidate-runner',
            'wheelClosuresVerified': len(outputs), 'packageNames': sorted(chosen),
            'next': 'docker compose -f ansible/playbooks/dependencies/compose.yaml build candidate-runner'}
