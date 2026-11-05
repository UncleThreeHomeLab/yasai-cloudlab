{{- define "observability.serviceMetrics" -}}
{{- if and .Values.enabled .Values.monitoringEnabled }}
{{- $policy := .Files.Get "policy.json" | fromJson }}
{{- $limits := $policy.http_collection }}
{{- $buckets := list }}
{{- range $limits.bucket_values }}{{ $buckets = append $buckets (regexQuoteMeta .) }}{{ end }}
{{- range $name, $binding := .Values.serviceMetrics }}
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: {{ printf "svc-%s" $name }}
  namespace: {{ $policy.namespace }}
  labels: {cloudlab.io/owner: observability-platform}
spec:
  namespaceSelector: {matchNames: [{{ $binding.namespace | quote }}]}
  selector:
    matchLabels: {app.kubernetes.io/name: {{ $name | quote }}, cloudlab.io/owner: {{ $binding.owner | quote }}}
    matchExpressions: [{key: cloudlab.io/release-analysis, operator: DoesNotExist}]
  podMetricsEndpoints:
    - port: http-metrics
      path: /metrics
      interval: {{ $limits.interval }}
      scrapeTimeout: {{ $limits.timeout }}
      honorLabels: false
      honorTimestamps: false
      relabelings:
        - {action: replace, targetLabel: namespace, replacement: {{ $binding.namespace | quote }}}
        - {action: replace, targetLabel: service, replacement: {{ $name | quote }}}
      metricRelabelings:
        - action: keep
          sourceLabels: [__name__]
          regex: 'cloudlab_http_requests_total|cloudlab_http_duration_seconds_(bucket|sum|count|max)'
        - action: keep
          sourceLabels: [route]
          regex: {{ printf "(%s|other)" (join "|" $binding.routes) | quote }}
        - action: keep
          sourceLabels: [method]
          regex: 'GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|CONNECT|TRACE'
        - {action: keep, sourceLabels: [status], regex: '[1-5][0-9][0-9]'}
        - {action: keep, sourceLabels: [traffic], regex: 'user|release|synthetic'}
        - action: keep
          sourceLabels: [__name__, le]
          regex: {{ printf "cloudlab_http_duration_seconds_bucket;(%s)|cloudlab_http_(requests_total|duration_seconds_(sum|count|max));" (join "|" $buckets) | quote }}
        - action: labelkeep
          regex: '__name__|namespace|service|job|instance|pod|container|endpoint|route|method|status|traffic|le'
  bodySizeLimit: {{ $limits.body_size_limit }}
  sampleLimit: {{ $limits.sample_limit }}
  targetLimit: {{ $limits.target_limit }}
  labelLimit: {{ $limits.label_limit }}
  labelNameLengthLimit: {{ $limits.label_name_length_limit }}
  labelValueLengthLimit: {{ $limits.label_value_length_limit }}
{{- end }}
{{- end }}
{{- end -}}
