{{- define "cloudlab.service.analysis" -}}
{{- if and (not .Values.renderDisabled) .Values.rollouts.enabled }}
{{- $policy := .Files.Get "release-policy.json" | fromJson }}
{{- $target := printf "namespace=%q,service=%q,revision=\"{{args.revision}}\"" .Release.Namespace .Values.name }}
{{- $selector := printf "%s,traffic=%q" $target $policy.traffic }}
{{- $window := printf "%ds" (int $policy.duration_seconds) }}
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata: {name: {{ .Values.name }}-release}
spec:
  args: [{name: revision}]
  metrics:
    {{- $queries := dict
      "scrape-health" (dict "query" (printf "min(up{%s})" $target) "condition" "result[0] == 1")
      "samples" (dict "query" (printf "sum(increase(cloudlab_http_requests_total{%s}[%s]))" $selector $window) "condition" (printf "result[0] >= %v" $policy.minimum_samples))
      "errors" (dict "query" (printf "sum(increase(cloudlab_http_requests_total{%s,status=~\"5..\"}[%s])) / sum(increase(cloudlab_http_requests_total{%s}[%s]))" $selector $window $selector $window) "condition" (printf "result[0] < %v" $policy.failure_rate))
      "p95" (dict "query" (printf "histogram_quantile(0.95,sum by(le)(increase(cloudlab_http_duration_seconds_bucket{%s}[%s])))" $selector $window) "condition" (printf "result[0] < %v" $policy.p95_seconds))
      "maximum" (dict "query" (printf "max(max_over_time(cloudlab_http_duration_seconds_max{%s}[%s]))" $selector $window) "condition" (printf "result[0] < %v" $policy.maximum_seconds)) }}
    {{- range $name, $metric := $queries }}
    - name: {{ $name }}
      initialDelay: {{ add (int $policy.duration_seconds) 10 }}s
      count: 1
      failureLimit: 0
      consecutiveErrorLimit: 0
      inconclusiveLimit: 0
      successCondition: {{ printf "len(result) == 1 && !isNaN(result[0]) && !isInf(result[0]) && %s" $metric.condition | quote }}
      provider:
        prometheus:
          address: http://cloudlab-prometheus.cloudlab-observability.svc:9090
          timeout: 10
          query: {{ $metric.query | quote }}
    {{- end }}
{{- end }}

{{- end }}
