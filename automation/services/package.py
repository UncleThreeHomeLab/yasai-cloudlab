"""Reproducible first-party chart and shared-code artifacts, without downloads."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def service_chart():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted((ROOT / 'charts/service').rglob('*')):
            if not path.is_file():
                continue
            raw = path.read_bytes().replace(b'\r\n', b'\n')
            info = tarfile.TarInfo('service/' + path.relative_to(ROOT / 'charts/service').as_posix())
            info.size, info.mode = len(raw), 0o644
            archive.addfile(info, io.BytesIO(raw))
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode='wb', filename='', mtime=0) as output:
        output.write(stream.getvalue())
    return compressed.getvalue()


def shared_code():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for relative in ('automation/identity/tokens.py', 'ansible/playbooks/data/files/s3.py'):
            info = zipfile.ZipInfo(Path(relative).name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o644 << 16
            archive.writestr(info, (ROOT / relative).read_bytes().replace(b'\r\n', b'\n'))
    return stream.getvalue()


def artifacts():
    return {'charts/service-0.1.0.tgz': service_chart(), 'lib.zip': shared_code()}


def build():
    base = ROOT / 'apps/notes'
    hashes = {}
    for name, raw in artifacts().items():
        path = base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    (base / 'artifact.lock.json').write_text(json.dumps(hashes, indent=2) + '\n')
    (ROOT / 'platform/delivery/services/github-app-key.tmpl').write_bytes(
        (ROOT / 'gitops/roots/public/github-app-key.tmpl').read_bytes().replace(b'\r\n', b'\n'))
    schema_path = ROOT / 'platform/delivery/services/values.schema.json'
    catalog_schema = json.loads(schema_path.read_text())
    catalog_schema['definitions']['service'] = json.loads((ROOT / 'charts/service/values.schema.json').read_text())
    schema_path.write_text(json.dumps(catalog_schema, indent=2) + '\n', newline='\n')


def check():
    base = ROOT / 'apps/notes'
    hashes = json.loads((base / 'artifact.lock.json').read_text())
    expected = artifacts()
    if set(hashes) != set(expected):
        raise ValueError('Notes artifact inventory differs')
    for name, raw in expected.items():
        if raw != (base / name).read_bytes() or hashlib.sha256(raw).hexdigest() != hashes[name]:
            raise ValueError('Notes artifact differs from its authoritative source: ' + name)
    if (ROOT / 'platform/delivery/services/github-app-key.tmpl').read_bytes().replace(b'\r\n', b'\n') != (ROOT / 'gitops/roots/public/github-app-key.tmpl').read_bytes().replace(b'\r\n', b'\n'):
        raise ValueError('Service Git credential template differs from its owning public interface')
    schema = json.loads((ROOT / 'charts/service/values.schema.json').read_text())
    catalog_schema = json.loads((ROOT / 'platform/delivery/services/values.schema.json').read_text())
    entry = catalog_schema['properties']['catalog']['items']['properties']
    if catalog_schema['definitions']['service'] != schema or any(
            source != {'$ref': '#/definitions/service'} for source in (
                entry['definition'], entry['notesValues']['properties']['web'], entry['notesValues']['properties']['api'])):
        raise ValueError('Catalog schema differs from the authoritative service schema')


if __name__ == '__main__':
    import sys
    if sys.argv[1:] == ['build']:
        build()
    else:
        check()
