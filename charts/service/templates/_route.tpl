{{- define "cloudlab.service.route" -}}
{{- if ne .Values.exposure.class "none" }}
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: {{ .Values.name }}
spec:
  parentRefs:
    - {name: cloudlab, namespace: {{ printf "cloudlab-gateway-%s" .Values.exposure.class }}, sectionName: https}
  hostnames: [{{ .Values.exposure.hostname | quote }}]
  rules:
    - matches:
        - path: {type: PathPrefix, value: {{ .Values.exposure.path | quote }}}
      backendRefs:
        {{- if .Values.rollouts.enabled }}
        - {name: {{ .Values.name }}, port: {{ .Values.exposure.port }}, weight: 100}
        - {name: {{ .Values.name }}-canary, port: {{ .Values.exposure.port }}, weight: 0}
        {{- else }}
        - {name: {{ .Values.name }}, port: {{ .Values.exposure.port }}}
        {{- end }}
{{- end }}
{{- range $index, $exposure := .Values.additionalExposures }}
{{- if eq $exposure.class "none" }}{{ fail "Additional exposure requires a public or private route" }}{{- end }}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: {{ printf "%s-extra-%d" $.Values.name $index }}
spec:
  parentRefs:
    - {name: cloudlab, namespace: {{ printf "cloudlab-gateway-%s" $exposure.class }}, sectionName: https}
  hostnames: [{{ $exposure.hostname | quote }}]
  rules:
    - matches:
        - path: {type: PathPrefix, value: {{ $exposure.path | quote }}}
      backendRefs:
        {{- if $.Values.rollouts.enabled }}
        - {name: {{ $.Values.name }}, port: {{ $exposure.port }}, weight: 100}
        - {name: {{ $.Values.name }}-canary, port: {{ $exposure.port }}, weight: 0}
        {{- else }}
        - {name: {{ $.Values.name }}, port: {{ $exposure.port }}}
        {{- end }}
{{- end }}

{{- end }}
