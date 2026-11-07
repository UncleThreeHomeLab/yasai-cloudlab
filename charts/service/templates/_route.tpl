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
{{- if .Values.routeOnly }}
{{- /* Composition keeps catalog-driven routes with exact host backends. */}}
{{- if ne .Values.exposure.class "none" }}
{{- $backend := include "cloudlab.service.backend" (dict "root" . "exposure" .Values.exposure) | fromJson }}
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
        - {name: {{ $backend.service }}, port: {{ $backend.port }}}
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
    - {name: cloudlab, namespace: {{ printf "cloudlab-gateway-%s" $exposure.class }}, sectionName: https}
  hostnames: [{{ $exposure.hostname | quote }}]
  rules:
    - matches:
        - path: {type: PathPrefix, value: {{ $exposure.path | quote }}}
      backendRefs:
        - {name: {{ $backend.service }}, port: {{ $backend.port }}}
{{- end }}
{{- else }}
{{- /* Ordinary routes derive only from validated exposure inputs. */}}
{{- if hasKey .Values.exposure "hostname" }}{{ fail "Ordinary service addresses come from exposure inputs" }}{{- end }}
{{- $file := .Values.exposureFile | default dict }}
{{- $routes := list }}
{{- if and $file (eq ($file.publication | default "") "published") }}
{{- $routes = append $routes (dict "class" "public" "hostname" $file.exposure.hostname "path" $file.exposure.path "port" $file.exposure.port) }}
{{- end }}
{{- range .Values.privateExposures | default list }}
{{- $routes = append $routes (dict "class" "private" "hostname" (required "Private exposure requires its zone-qualified hostname" .hostname) "path" .path "port" .port) }}
{{- end }}
{{- $retiredExposure := and $file (eq ($file.publication | default "") "retired") }}
{{- if and (not $routes) (ne .Values.exposure.class "none") (not $retiredExposure) }}{{ fail "Exposed ordinary service lacks its exposure input" }}{{- end }}
{{- range $index, $route := $routes }}
{{- if $index }}
---
{{ end }}
{{- $backend := include "cloudlab.service.backend" (dict "root" $ "exposure" $route) | fromJson }}
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: {{ if $index }}{{ printf "%s-extra-%d" $.Values.name (sub $index 1) }}{{ else }}{{ $.Values.name }}{{ end }}
spec:
  parentRefs:
    {{- if $.Values.rollouts.enabled }}
    - {group: gateway.networking.k8s.io, kind: Gateway, name: cloudlab, namespace: {{ printf "cloudlab-gateway-%s" $route.class }}, sectionName: https}
    {{- else }}
    - {name: cloudlab, namespace: {{ printf "cloudlab-gateway-%s" $route.class }}, sectionName: https}
    {{- end }}
  hostnames: [{{ $route.hostname | quote }}]
  rules:
    - matches:
        - path: {type: PathPrefix, value: {{ $route.path | quote }}}
      backendRefs:
        {{- if $.Values.rollouts.enabled }}
        - {group: '', kind: Service, name: {{ $.Values.name }}, port: {{ $route.port }}, weight: 100}
        - {group: '', kind: Service, name: {{ $.Values.name }}-canary, port: {{ $route.port }}, weight: 0}
        {{- else }}
        - {name: {{ $backend.service }}, port: {{ $backend.port }}}
        {{- end }}
{{- end }}
{{- end }}

{{- end }}
