{{- define "cloudlab.service.backend" -}}
{{- $backend := dict "service" .root.Values.name "port" .exposure.port -}}
{{- if and .root.Values.routeOnly .root.Values.routeBackends -}}
{{- $host := .exposure.hostname -}}
{{- if not (hasKey .root.Values.routeBackends $host) }}{{ fail "Route backend lacks exact host approval" }}{{ end -}}
{{- $backend = index .root.Values.routeBackends $host -}}
{{- end -}}
{{- $backend | toJson -}}
{{- end -}}

{{- define "cloudlab.service.route" -}}
{{- if ne .Values.exposure.class "none" }}
{{- $backend := include "cloudlab.service.backend" (dict "root" . "exposure" .Values.exposure) | fromJson }}
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: {{ .Values.name }}
spec:
  parentRefs:
    {{- if .Values.rollouts.enabled }}
    - {group: gateway.networking.k8s.io, kind: Gateway, name: cloudlab, namespace: {{ printf "cloudlab-gateway-%s" .Values.exposure.class }}, sectionName: https}
    {{- else }}
    - {name: cloudlab, namespace: {{ printf "cloudlab-gateway-%s" .Values.exposure.class }}, sectionName: https}
    {{- end }}
  hostnames: [{{ .Values.exposure.hostname | quote }}]
  rules:
    - matches:
        - path: {type: PathPrefix, value: {{ .Values.exposure.path | quote }}}
      backendRefs:
        {{- if .Values.rollouts.enabled }}
        - {group: '', kind: Service, name: {{ .Values.name }}, port: {{ .Values.exposure.port }}, weight: 100}
        - {group: '', kind: Service, name: {{ .Values.name }}-canary, port: {{ .Values.exposure.port }}, weight: 0}
        {{- else }}
        - {name: {{ $backend.service }}, port: {{ $backend.port }}}
        {{- end }}
{{- end }}
{{- range $index, $exposure := .Values.additionalExposures }}
{{- if eq $exposure.class "none" }}{{ fail "Additional exposure requires a public or private route" }}{{- end }}
{{- $backend := include "cloudlab.service.backend" (dict "root" $ "exposure" $exposure) | fromJson }}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: {{ printf "%s-extra-%d" $.Values.name $index }}
spec:
  parentRefs:
    {{- if $.Values.rollouts.enabled }}
    - {group: gateway.networking.k8s.io, kind: Gateway, name: cloudlab, namespace: {{ printf "cloudlab-gateway-%s" $exposure.class }}, sectionName: https}
    {{- else }}
    - {name: cloudlab, namespace: {{ printf "cloudlab-gateway-%s" $exposure.class }}, sectionName: https}
    {{- end }}
  hostnames: [{{ $exposure.hostname | quote }}]
  rules:
    - matches:
        - path: {type: PathPrefix, value: {{ $exposure.path | quote }}}
      backendRefs:
        {{- if $.Values.rollouts.enabled }}
        - {group: '', kind: Service, name: {{ $.Values.name }}, port: {{ $exposure.port }}, weight: 100}
        - {group: '', kind: Service, name: {{ $.Values.name }}-canary, port: {{ $exposure.port }}, weight: 0}
        {{- else }}
        - {name: {{ $backend.service }}, port: {{ $backend.port }}}
        {{- end }}
{{- end }}

{{- end }}
