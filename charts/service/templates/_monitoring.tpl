{{/* Canonical collection validator. package.py projects this into its two consumers. */}}
{{- define "cloudlab.service.monitoring" -}}
{{- $v := .definition | toJson | fromJson -}}
{{- $result := dict "enabled" false -}}
{{- if dig "monitoring" "enabled" false $v -}}
{{- $a := .approval | default dict -}}
{{- if or (hasKey $a "composition") (ne ($a.chartPath | default "charts/service") "charts/service") (dig "rollouts" "enabled" false $v) -}}
{{- fail "HTTP collection supports only ordinary non-rollout service charts" -}}
{{- end -}}
{{- if gt (int ($v.replicas | default 1)) 4 }}{{ fail "HTTP collection permits at most four targets" }}{{ end -}}
{{- $metrics := $v.monitoring.metrics -}}
{{- $ports := dict -}}{{- $numbers := dict -}}{{- $port := 0 -}}
{{- range $v.ports -}}
{{- $number := printf "%d" (int .port) -}}
{{- if or (hasKey $ports .name) (hasKey $numbers $number) }}{{ fail "HTTP collection requires unique dedicated named TCP ports" }}{{ end -}}
{{- $_ := set $ports .name (int .port) -}}{{- $_ := set $numbers $number true -}}
{{- if eq .name "http-metrics" -}}
{{- if ne (.protocol | default "TCP") "TCP" }}{{ fail "HTTP collection requires TCP" }}{{ end -}}
{{- $port = int .port -}}
{{- end -}}
{{- end -}}
{{- if not $port }}{{ fail "HTTP collection requires the dedicated http-metrics port" }}{{ end -}}
{{- range concat (list ($v.exposure | default (dict "class" "none"))) ($v.additionalExposures | default list) -}}
{{- if ne .class "none" -}}
{{- if or (not (hasKey . "port")) (eq (int .port) $port) (not (hasKey $numbers (printf "%d" (int .port)))) }}{{ fail "Exposures require explicit declared non-metrics ports" }}{{ end -}}
{{- end -}}
{{- end -}}
{{- range $v.health | default dict -}}
{{- if or (not (hasKey $ports .port)) (eq (int (get $ports .port)) $port) }}{{ fail "Health probes require declared non-metrics ports" }}{{ end -}}
{{- end -}}
{{- $result = dict "enabled" true "port" $port "routes" $metrics.routes -}}
{{- end -}}
{{- toJson $result -}}
{{- end -}}
