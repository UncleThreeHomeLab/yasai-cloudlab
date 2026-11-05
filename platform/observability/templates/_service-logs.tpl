{{- define "observability.serviceLogs" -}}
{{- $limits := (.Files.Get "policy.json" | fromJson).http_logs -}}
{{- range $name, $binding := .Values.serviceLogs }}
{{- $id := printf "svc_%s" (replace "-" "_" $name) -}}
{{- $routes := printf "^(%s|other)$" (join "|" $binding.routes) -}}
{{- $errors := printf "^(%s)$" (join "|" $limits.error_codes) -}}
{{- $safe := printf `{{ if and (eq (printf "%%v" .kind) "request") (regexMatch %q (printf "%%v" .route)) (regexMatch "^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|CONNECT|TRACE)$" (printf "%%v" .method)) (regexMatch "^[1-5][0-9]{2}$" (printf "%%v" .status)) (regexMatch %q (printf "%%v" .duration)) (or (eq .trace_id nil) (eq (printf "%%v" .trace_id) "") (and (regexMatch "^[a-f0-9]{32}$" (printf "%%v" .trace_id)) (not (regexMatch "^0{32}$" (printf "%%v" .trace_id))))) }}{"kind":"request","service":%q,"method":"{{ .method }}","route":"{{ .route }}","status":{{ .status }},"duration_ms":{{ .duration }}{{ if .trace_id }},"trace_id":"{{ .trace_id }}"{{ end }}}{{ else if and (eq (printf "%%v" .kind) "error") (regexMatch %q (printf "%%v" .code)) (or (eq .trace_id nil) (eq (printf "%%v" .trace_id) "") (and (regexMatch "^[a-f0-9]{32}$" (printf "%%v" .trace_id)) (not (regexMatch "^0{32}$" (printf "%%v" .trace_id))))) }}{"kind":"error","service":%q,"code":"{{ .code }}"{{ if .trace_id }},"trace_id":"{{ .trace_id }}"{{ end }}}{{ end }}` $routes $limits.duration_pattern $name $errors $name -}}

discovery.kubernetes {{ $id | quote }} {
  role = "pod"
  namespaces { names = [{{ $binding.namespace | quote }}] }
  selectors {
    role = "pod"
    label = {{ printf "app.kubernetes.io/name=%s,cloudlab.io/owner=%s,cloudlab.io/log-profile=%s,!cloudlab.io/release-analysis" $name $binding.owner $binding.profile | quote }}
  }
}
discovery.relabel {{ $id | quote }} {
  targets = discovery.kubernetes.{{ $id }}.targets
  rule {
    source_labels = ["__meta_kubernetes_pod_container_name"]
    regex = "application"
    action = "keep"
  }
}
loki.source.kubernetes {{ $id | quote }} {
  targets = discovery.relabel.{{ $id }}.output
  forward_to = [loki.process.{{ $id }}.receiver]
}
loki.process {{ $id | quote }} {
  stage.drop {
    longer_than = {{ $limits.max_line_size | quote }}
    drop_counter_reason = "generic_oversize"
  }
  stage.limit {
    rate = {{ $limits.rate }}
    burst = {{ $limits.burst }}
    drop = true
  }
  stage.json {
    expressions = { kind = "kind", method = "method", route = "route", status = "status", duration = "duration_ms", trace_id = "trace_id", code = "code" }
  }
  stage.template {
    source = "safe_line"
    template = {{ `{{ "" }}` | toJson }}
  }
  stage.template {
    source = "safe_line"
    template = {{ $safe | toJson }}
  }
  stage.drop {
    source = "safe_line"
    expression = "^$"
    drop_counter_reason = "generic_invalid"
  }
  stage.static_labels { values = { service = {{ $name | quote }} } }
  stage.labels { values = { kind = "kind" } }
  stage.label_keep { values = ["service", "kind"] }
  stage.output { source = "safe_line" }
  forward_to = [loki.write.local.receiver]
}
{{ end }}
{{- end -}}
