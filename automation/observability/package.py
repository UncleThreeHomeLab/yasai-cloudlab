"""Rebuild checksum-locked chart patches for declarative monitoring owners."""
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


def kiali_declarative(raw):
    output, changes = io.BytesIO(), 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as source:
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w') as target:
                for original in source:
                    if not original.isfile() or original.name.startswith('/') or '..' in Path(original.name).parts:
                        raise ValueError('Unexpected Kiali chart member')
                    data = source.extractfile(original).read()
                    if original.name == 'kiali-server/templates/_helpers.tpl':
                        start = data.index(b'{{- define "kiali-server.accessible-namespaces" -}}')
                        end = data.index(b'\n{{/*', start)
                        # Argo Helm rendering has no live lookup; exact namespace inputs remain declarative.
                        replacement = b'''{{- define "kiali-server.accessible-namespaces" -}}
{{- $namespaces := list .Release.Namespace -}}
{{- range .Values.deployment.discovery_selectors.default -}}
{{- $selected := list -}}
{{- if .matchLabels -}}
{{- if ne (len .matchLabels) 1 }}{{ fail "Kiali requires exact namespace selectors" }}{{ end -}}
{{- $selected = list (index .matchLabels "kubernetes.io/metadata.name") -}}
{{- else -}}
{{- if ne (len (.matchExpressions | default list)) 1 }}{{ fail "Kiali requires exact namespace selectors" }}{{ end -}}
{{- $expression := index .matchExpressions 0 -}}
{{- if or (ne $expression.key "kubernetes.io/metadata.name") (ne $expression.operator "In") }}{{ fail "Kiali requires exact namespace selectors" }}{{ end -}}
{{- $selected = $expression.values -}}
{{- end -}}
{{- range $name := $selected -}}
{{- if not (has $name (list "cloudlab-observability" "cloudlab-app-notes" "istio-system" "cloudlab-gateway-public" "cloudlab-gateway-private")) }}{{ fail "Kiali namespace outside approved scope" }}{{ end -}}
{{- if not (has $name $namespaces) }}{{ $namespaces = append $namespaces $name }}{{ end -}}
{{- end -}}
{{- end -}}
{{- join "," $namespaces -}}
{{- end -}}
'''
                        data = data[:start] + replacement + data[end:]
                        changes += 1
                    if original.name == 'kiali-server/templates/role-viewer.yaml':
                        for block in (b'- apiGroups: [""]\n  resources:\n  - pods/portforward\n  verbs:\n  - create\n',
                                      b'- apiGroups: ["authentication.k8s.io"]\n  resources:\n  - tokenreviews\n  verbs:\n  - create\n'):
                            if data.count(block) != 1: raise ValueError('Pinned Kiali viewer RBAC changed')
                            data = data.replace(block, b'')
                            changes += 1
                    member = tarfile.TarInfo(original.name)
                    member.mode, member.size = 0o644, len(data)
                    target.addfile(member, io.BytesIO(data))
    if changes != 3: raise ValueError('Pinned Kiali declarative patch changed')
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
        if name in ('prometheus', 'kiali'):
            raw = (path / 'upstream.tgz').read_bytes()
            if hashlib.sha256(raw).hexdigest() != lock['upstream_sha256']:
                raise ValueError('Upstream monitoring chart checksum mismatch')
            data = retained(raw) if name == 'prometheus' else kiali_declarative(raw)
            (path / lock['archive']).write_bytes(data)
            lock['sha256'] = hashlib.sha256(data).hexdigest()
            (path / 'artifact.lock.json').write_text(json.dumps(lock, indent=2) + '\n')
        (path / 'values.json').write_text(json.dumps({lock['chart']: values(name)}, indent=2) + '\n')


if __name__ == '__main__':
    build()
