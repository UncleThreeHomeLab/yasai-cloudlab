"""Reproduce Istio chart archives from its checksum-pinned official release."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[4] / 'platform/connectivity/istio'
_LOCK = json.loads((ROOT / 'base/artifact.lock.json').read_text())
VERSION = _LOCK['version']
RELEASE_SHA256 = _LOCK['source_release_sha256']
PATHS = {'base': 'base', 'istiod': 'istio-control/istio-discovery', 'cni': 'istio-cni', 'ztunnel': 'ztunnel'}
MARKER = b'{{$asDict | toYaml }}'
ANNOTATION = (b'{{- $_ := set $asDict.metadata "annotations" (merge '
              b'(dict "argocd.argoproj.io/sync-options" "ServerSideApply=true,Prune=false,Delete=false") '
              b'(default (dict) $asDict.metadata.annotations)) }}\n')


def archive(files):
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w') as target:
            for name, data in sorted(files.items()):
                item = tarfile.TarInfo(name)
                item.mode, item.size = 0o644, len(data)
                target.addfile(item, io.BytesIO(data))
    return output.getvalue()


def from_release(raw, component, *, version=None, sha256=None):
    if hashlib.sha256(raw).hexdigest() != (sha256 or RELEASE_SHA256):
        raise ValueError('Istio release archive checksum mismatch')
    prefix = 'istio-' + (version or VERSION) + '/manifests/charts/' + PATHS[component] + '/'
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as source:
        for member in source:
            if not member.name.startswith(prefix) or member.isdir():
                continue
            name = component + '/' + member.name.removeprefix(prefix)
            if not member.isfile() or '..' in Path(name).parts or name in files:
                raise ValueError('Unexpected Istio chart member')
            files[name] = source.extractfile(member).read()
    if component + '/Chart.yaml' not in files:
        raise ValueError('Istio chart missing from release archive')
    return archive(files)


def patched(raw, component):
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as source:
        for member in source:
            if not member.isfile() or member.name.startswith('/') or '..' in Path(member.name).parts or member.name in files:
                raise ValueError('Unexpected Istio chart member')
            files[member.name] = source.extractfile(member).read()
    if component == 'base':
        name = 'base/templates/crds.yaml'
        if files[name].count(MARKER) != 1 or ANNOTATION in files[name]:
            raise ValueError('Istio CRD template changed')
        files[name] = files[name].replace(MARKER, ANNOTATION + MARKER)
    return archive(files)


def verify(component):
    root = ROOT / component
    lock = json.loads((root / 'artifact.lock.json').read_text())
    source = (root / 'upstream.tgz').read_bytes()
    path = (root / lock['archive']).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError('Istio archive escapes its module')
    data = path.read_bytes()
    if (hashlib.sha256(source).hexdigest() != lock['upstream_sha256']
            or hashlib.sha256(data).hexdigest() != lock['sha256'] or patched(source, component) != data):
        raise ValueError('Istio chart checksum or narrow patch mismatch')
    return lock
