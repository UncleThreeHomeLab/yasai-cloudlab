{{/* Canonical collection validator. The defined template must match platform/observability/gitops/templates/_monitoring.tpl. */}}
{{- define "cloudlab.service.monitoring" -}}
{{- $v := .definition | toJson | fromJson -}}
{{- $metricsEnabled := dig "monitoring" "metrics" "enabled" false $v -}}
{{- $logsEnabled := dig "monitoring" "logs" "enabled" false $v -}}
{{- if dig "monitoring" "traces" "enabled" false $v }}{{ fail "Generic service traces require qualified ambient workload attribution; this integration supports metrics and logs" }}{{ end -}}
{{- $result := dict "enabled" false "routes" list "metrics" (dict "enabled" false) "logs" (dict "enabled" false) -}}
{{- if and (not (dig "monitoring" "enabled" false $v)) (or $metricsEnabled $logsEnabled) }}{{ fail "Enabled signals require monitoring enabled" }}{{ end -}}
{{- if dig "monitoring" "enabled" false $v -}}
{{- if not (or $metricsEnabled $logsEnabled) }}{{ fail "Monitoring requires metrics or logs" }}{{ end -}}
{{- $a := .approval | default dict -}}
{{- if or (hasKey $a "composition") (ne ($a.chartPath | default "charts/service") "charts/service") (dig "rollouts" "enabled" false $v) -}}
{{- fail "HTTP collection supports only ordinary non-rollout service charts" -}}
{{- end -}}
{{- $result = dict "enabled" true "routes" $v.monitoring.routes "metrics" (dict "enabled" false) "logs" (dict "enabled" $logsEnabled "profile" "cloudlab-http-json-v1") -}}
{{- if $metricsEnabled -}}
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
{{- $_ := set $result "metrics" (dict "enabled" true "port" $port) -}}
{{- end -}}
{{- end -}}
{{- toJson $result -}}
{{- end -}}
