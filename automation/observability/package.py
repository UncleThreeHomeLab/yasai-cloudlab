"""Retain monitoring CRDs without changing upstream chart behavior."""
import gzip
import hashlib
import io
import json
import re
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'platform/observability'


def retained(raw):
    output = io.BytesIO()
    count = 0
    authentication = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as source:
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w') as target:
                for original in source:
                    if not original.isfile() or original.name.startswith('/') or '..' in Path(original.name).parts:
                        raise ValueError('Unexpected monitoring chart member')
                    data = source.extractfile(original).read()
                    for component in ('kubelet', 'kubeApiServer'):
                        marker = ('{{- with .Values.' + component + '.serviceMonitor.authorization }}').encode()
                        if marker in data:
                            replacement = ('{{- with .Values.' + component + '.serviceMonitor.bearerTokenFile }}\n'
                                'bearerTokenFile: {{ . | quote }}\n{{- end }}\n').encode() + marker
                            # Keep the endpoint indentation of its existing authorization field.
                            if component == 'kubeApiServer':
                                replacement = replacement.replace(b'\nbearerTokenFile:', b'\n    bearerTokenFile:')
                            data = data.replace(marker, replacement)
                            authentication += 1
                    if '/crds/crds/' in original.name and b'kind: CustomResourceDefinition\n' in data:
                        marker = b'  annotations:\n'
                        if data.count(marker) < 1:
                            raise ValueError('Monitoring CRD annotations missing')
                        data = data.replace(marker, marker + b'    argocd.argoproj.io/sync-options: ServerSideApply=true,Prune=false,Delete=false\n', 1)
                        # YAML 1.1 treats unquoted '=' as a special value tag.
                        data = re.sub(rb'(?m)^(\s+-) =$' , rb'\1 "="', data)
                        count += 1
                    member = tarfile.TarInfo(original.name)
                    member.mode, member.size = 0o644, len(data)
                    target.addfile(member, io.BytesIO(data))
    if count != 10 or authentication != 2:
        raise ValueError('Pinned monitoring CRD inventory changed')
    return output.getvalue()


def build():
    from automation.observability.values import values
    from automation.observability.slo import build as build_slo
    from automation.observability.configuration import audit_rules
    build_slo()
    resource = {'apiVersion': 'monitoring.coreos.com/v1', 'kind': 'PrometheusRule',
                'metadata': {'name': 'identity-evidence', 'namespace': 'cloudlab-observability'}, 'spec': audit_rules()}
    (BASE / 'prometheus/templates/identity-alerts.json').write_text(json.dumps(resource, indent=2) + '\n')
    for name in ('prometheus', 'loki', 'tempo', 'alloy', 'kiali'):
        path = BASE / name
        lock = json.loads((path / 'artifact.lock.json').read_text())
        if name == 'prometheus':
            raw = (path / 'upstream.tgz').read_bytes()
            if hashlib.sha256(raw).hexdigest() != lock['upstream_sha256']:
                raise ValueError('Upstream monitoring chart checksum mismatch')
            data = retained(raw)
            (path / lock['archive']).write_bytes(data)
            lock['sha256'] = hashlib.sha256(data).hexdigest()
            (path / 'artifact.lock.json').write_text(json.dumps(lock, indent=2) + '\n')
        (path / 'values.json').write_text(json.dumps({lock['chart']: values(name)}, indent=2) + '\n')


if __name__ == '__main__':
    build()
