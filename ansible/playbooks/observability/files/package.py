"""Rebuild checksum-locked chart patches for declarative monitoring owners."""
import gzip
import hashlib
import io
import json
import re
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / 'platform/observability'


def projections(check=False):
    """Project canonical resource templates into their native chart owners."""
    for component, names in {
        'prometheus': ('baseline-monitors', 'service-metrics', 'service-rules', 'routes'),
        'kiali': ('routes',),
    }.items():
        inputs = [(BASE / 'policy.json', BASE / component / 'policy.json')]
        inputs += [(BASE / 'templates' / ('_' + name + '.tpl'),
                    BASE / component / 'templates' / ('_' + name + '.tpl')) for name in names]
        for source, target in inputs:
            content = source.read_bytes()
            if check:
                if not target.exists() or target.read_bytes() != content:
                    raise ValueError('Native observability projection differs: ' + str(target.relative_to(BASE)))
            else:
                target.write_bytes(content)


def loki_declarative(raw):
    """Correct the native governing Service without changing legacy chart output."""
    output, seen = io.BytesIO(), set()
    target_name = 'loki/templates/single-binary/service-headless.yaml'
    source_hash = '720dffcd657bcca2c71f3debd41c88ca802868b12f87c04b6a305a719e8532f9'
    require_target = False
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError('Loki chart exceeds bound')
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as compressed:
        expanded = compressed.read(16 * 1024 * 1024 + 1)
    if len(expanded) > 16 * 1024 * 1024:
        raise ValueError('Expanded Loki chart exceeds bound')
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as source:
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w') as target:
                for original in source:
                    if (not original.isfile() or original.pax_headers or original.name.startswith('/') or
                            '\\' in original.name or {'', '.', '..'} & set(original.name.split('/')) or
                            original.name in seen or original.size > 4 * 1024 * 1024):
                        raise ValueError('Unexpected Loki chart member')
                    seen.add(original.name)
                    data = source.extractfile(original).read()
                    if original.name == target_name:
                        if hashlib.sha256(data).hexdigest() != source_hash:
                            raise ValueError('Pinned Loki headless Service template changed')
                        guard = b'''{{- $cloudlabNative := false -}}
{{- if hasKey .Values "cloudlabNativeLifecycle" -}}
{{- if not (kindIs "bool" .Values.cloudlabNativeLifecycle) }}{{ fail "cloudlabNativeLifecycle must be a boolean" }}{{ end -}}
{{- $cloudlabNative = .Values.cloudlabNativeLifecycle -}}
{{- end -}}
'''
                        marker = b'{{ include "loki.name" . }}-headless'
                        if data.count(marker) != 1:
                            raise ValueError('Pinned Loki headless Service name changed')
                        data = guard + data.replace(marker,
                            b'{{ if $cloudlabNative }}{{ include "loki.singleBinaryFullname" . }}{{ else }}{{ include "loki.name" . }}{{ end }}-headless')
                        require_target = True
                    member = tarfile.TarInfo(original.name)
                    member.mode, member.size = 0o644, len(data)
                    target.addfile(member, io.BytesIO(data))
    if not require_target:
        raise ValueError('Pinned Loki headless Service template missing')
    return output.getvalue()


def retained(raw):
    output = io.BytesIO()
    count = 0
    authentication = 0
    storage = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as source:
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w') as target:
                for original in source:
                    if not original.isfile() or original.name.startswith('/') or '..' in Path(original.name).parts:
                        raise ValueError('Unexpected monitoring chart member')
                    data = source.extractfile(original).read()
                    if original.name == 'kube-prometheus-stack/templates/alertmanager/alertmanager.yaml':
                        if hashlib.sha256(data).hexdigest() != '85bd50250d8f6400cba2fcc6ea9777b7b0b31dac71e6900f4c39048d0a07cfce':
                            raise ValueError('Pinned Alertmanager template changed')
                        marker = b'''{{- if .Values.alertmanager.alertmanagerSpec.storage }}
  storage:
{{ tpl (toYaml .Values.alertmanager.alertmanagerSpec.storage | indent 4) . }}
{{- end }}'''
                        if data.count(marker) != 1:
                            raise ValueError('Pinned Alertmanager storage block changed')
                        guard = b'''{{- $cloudlabNative := false -}}
{{- if hasKey .Values "cloudlabNativeLifecycle" -}}
{{- if not (kindIs "bool" .Values.cloudlabNativeLifecycle) }}{{ fail "cloudlabNativeLifecycle must be a boolean" }}{{ end -}}
{{- $cloudlabNative = .Values.cloudlabNativeLifecycle -}}
{{- end -}}
{{- if $cloudlabNative -}}
{{- $storage := .Values.alertmanager.alertmanagerSpec.storage -}}
{{- if not (kindIs "map" $storage) }}{{ fail "Native Alertmanager requires explicit storage" }}{{ end -}}
{{- range $key, $_ := $storage -}}
{{- if not (has $key (list "emptyDir" "volumeClaimTemplate")) }}{{ fail "Unsupported native Alertmanager storage mode" }}{{ end -}}
{{- end -}}
{{- if or (not (kindIs "map" $storage.volumeClaimTemplate)) (empty $storage.volumeClaimTemplate) }}{{ fail "Native Alertmanager requires a volumeClaimTemplate" }}{{ end -}}
{{- end -}}
'''
                        replacement = b'''{{- if $cloudlabNative }}
  storage:
{{ tpl (toYaml (dict "volumeClaimTemplate" .Values.alertmanager.alertmanagerSpec.storage.volumeClaimTemplate) | indent 4) . }}
{{- else }}
''' + marker + b'\n{{- end }}'
                        data = guard + data.replace(marker, replacement)
                        storage += 1
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
    if count != 10 or authentication != 2 or storage != 1:
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
{{- if not (has $name (list __KIALI_NAMESPACES__)) }}{{ fail "Kiali namespace outside approved scope" }}{{ end -}}
{{- if not (has $name $namespaces) }}{{ $namespaces = append $namespaces $name }}{{ end -}}
{{- end -}}
{{- end -}}
{{- join "," $namespaces -}}
{{- end -}}
'''
                        policy = json.loads((BASE / 'policy.json').read_bytes())
                        replacement = replacement.replace(b'__KIALI_NAMESPACES__',
                            ' '.join(json.dumps(name) for name in policy['kiali']['namespaces']).encode())
                        data = data[:start] + replacement + data[end:]
                        changes += 1
                    if original.name == 'kiali-server/templates/role-viewer.yaml':
                        for block in (b'- apiGroups: [""]\n  resources:\n  - pods/portforward\n  verbs:\n  - create\n',
                                      b'- apiGroups: ["authentication.k8s.io"]\n  resources:\n  - tokenreviews\n  verbs:\n  - create\n'):
                            if data.count(block) != 1: raise ValueError('Pinned Kiali viewer RBAC changed')
                            data = data.replace(block, b'')
                            changes += 1
                    if original.name in ('kiali-server/templates/role-viewer.yaml', 'kiali-server/templates/rolebinding.yaml'):
                        marker = b'{{- range $namespace := $namespaces }}'
                        if data.count(marker) != 1:
                            raise ValueError('Pinned Kiali namespace RBAC loop changed')
                        # Argo owns its backend reader; telemetry cannot write into argocd.
                        data = data.replace(marker, b'{{- $namespaces = without $namespaces "argocd" -}}\n' + marker)
                        changes += 1
                    member = tarfile.TarInfo(original.name)
                    member.mode, member.size = 0o644, len(data)
                    target.addfile(member, io.BytesIO(data))
    if changes != 5: raise ValueError('Pinned Kiali declarative patch changed')
    return output.getvalue()


def tempo_protocols(raw):
    """Declare protocols without changing upstream service port names or numbers."""
    protocols = {'tempo-prom-metrics': 'http', 'jaeger-metrics': 'http', 'tempo-query-jaeger-ui': 'http',
                 'tempo-jaeger-thrift-http': 'http', 'grpc-tempo-jaeger': 'grpc', 'tempo-zipkin': 'http',
                 'tempo-otlp-legacy': 'grpc', 'tempo-otlp-http-legacy': 'http',
                 'grpc-tempo-otlp': 'grpc', 'tempo-otlp-http': 'http'}
    output, changes = io.BytesIO(), 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as source:
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w') as target:
                for original in source:
                    if not original.isfile() or original.name.startswith('/') or '..' in Path(original.name).parts:
                        raise ValueError('Unexpected Tempo chart member')
                    data = source.extractfile(original).read()
                    if original.name == 'tempo/templates/_ports.tpl':
                        for name, protocol in protocols.items():
                            marker = ('- name: ' + name + '\n').encode()
                            if data.count(marker) != 1:
                                raise ValueError('Pinned Tempo port inventory changed')
                            data = data.replace(marker, marker + ('  appProtocol: ' + protocol + '\n').encode())
                            changes += 1
                    member = tarfile.TarInfo(original.name)
                    member.mode, member.size = 0o644, len(data)
                    target.addfile(member, io.BytesIO(data))
    if changes != len(protocols):
        raise ValueError('Pinned Tempo protocol patch changed')
    return output.getvalue()


def build():
    from playbooks.observability.files.values import values
    from playbooks.observability.files.slo import build as build_slo
    from playbooks.observability.files.configuration import audit_rules
    projections()
    build_slo()
    resource = {'apiVersion': 'monitoring.coreos.com/v1', 'kind': 'PrometheusRule',
                'metadata': {'name': 'identity-evidence', 'namespace': 'cloudlab-observability'}, 'spec': audit_rules()}
    (BASE / 'prometheus/templates/identity-alerts.json').write_text(json.dumps(resource, indent=2) + '\n')
    for name in ('prometheus', 'loki', 'tempo', 'alloy', 'kiali'):
        path = BASE / name
        lock = json.loads((path / 'artifact.lock.json').read_text())
        patchers = {'prometheus': retained, 'kiali': kiali_declarative, 'tempo': tempo_protocols, 'loki': loki_declarative}
        if name in patchers:
            raw = (path / 'upstream.tgz').read_bytes()
            if hashlib.sha256(raw).hexdigest() != lock['upstream_sha256']:
                raise ValueError('Upstream monitoring chart checksum mismatch')
            data = patchers[name](raw)
            (path / lock['archive']).write_bytes(data)
            lock['sha256'] = hashlib.sha256(data).hexdigest()
            (path / 'artifact.lock.json').write_text(json.dumps(lock, indent=2) + '\n')
        (path / 'values.json').write_text(json.dumps({lock['chart']: values(name)}, indent=2) + '\n')


if __name__ == '__main__':
    build()
