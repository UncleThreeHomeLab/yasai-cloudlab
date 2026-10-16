"""Rebuild the locked Harbor chart with explicit vault, rollout and discovery fields."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

BASE = Path(__file__).resolve().parents[2] / 'platform/harbor'


def patched(raw):
    output, changes = io.BytesIO(), 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as source:
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as target:
                for original in source:
                    if not original.isfile() or original.name.startswith('/') or '..' in Path(original.name).parts:
                        raise ValueError('Unexpected Harbor chart member')
                    data = source.extractfile(original).read()
                    replacements = {}
                    if original.name == 'harbor/templates/database/database-secret.yaml':
                        replacements = {b'{{- if eq .Values.database.type "internal" -}}':
                            b'{{- if and (eq .Values.database.type "internal") (not .Values.database.external.existingSecret) -}}'}
                    if original.name == 'harbor/templates/database/database-ss.yaml':
                        replacements = {b'name: "{{ template "harbor.database" . }}"\n        env:':
                            b'name: {{ .Values.database.external.existingSecret | default (include "harbor.database" .) | quote }}\n        env:',
                            b'  replicas: 1\n': b'  replicas: {{ .Values.database.internal.replicas }}\n'}
                    if original.name == 'harbor/templates/redis/statefulset.yaml':
                        replacements = {b'  replicas: 1\n': b'  replicas: {{ .Values.redis.internal.replicas }}\n'}
                    if original.name in ('harbor/templates/core/core-dpl.yaml',
                                         'harbor/templates/nginx/deployment.yaml',
                                         'harbor/templates/portal/deployment.yaml'):
                        replacements = {b'spec:\n  replicas:': b'spec:\n  strategy:\n    type: Recreate\n  replicas:'}
                    if original.name == 'harbor/templates/core/core-dpl.yaml':
                        replacements.update({
                            b'    spec:\n      securityContext:':
                            b'    spec:\n      {{- with .Values.core.hostAliases }}\n      hostAliases:\n        {{- toYaml . | nindent 8 }}\n      {{- end }}\n      securityContext:',
                            b'        - name: token-service-private-key\n          mountPath: /etc/core/private_key.pem\n          subPath: tls.key':
                            b'        - name: psc\n          mountPath: /etc/core/private_key.pem\n          subPath: registry-private-key.pem\n          readOnly: true',
                            b'      - name: psc\n        emptyDir: {}':
                            b'      - name: psc\n        emptyDir: {medium: Memory, sizeLimit: 1Mi}'})
                    for before, after in replacements.items():
                        if data.count(before) != 1:
                            raise ValueError('Pinned Harbor template changed')
                        data = data.replace(before, after)
                        changes += 1
                    member = tarfile.TarInfo(original.name)
                    member.mode, member.size = 0o644, len(data)
                    target.addfile(member, io.BytesIO(data))
    if changes != 10:
        raise ValueError('Pinned Harbor field patch changed')
    return output.getvalue()


def build():
    from automation.harbor.values import values
    directory = BASE / 'server'
    lock = json.loads((directory / 'artifact.lock.json').read_text())
    raw = (directory / 'upstream.tgz').read_bytes()
    if hashlib.sha256(raw).hexdigest() != lock['upstream_sha256']:
        raise ValueError('Harbor upstream chart checksum mismatch')
    archive = patched(raw)
    if hashlib.sha256(archive).hexdigest() != lock['sha256']:
        raise ValueError('Harbor patched chart checksum mismatch')
    (directory / lock['archive']).write_bytes(archive)
    (directory / 'values.json').write_text(json.dumps({'harbor': values()}, indent=2) + '\n')


if __name__ == '__main__':
    build()
