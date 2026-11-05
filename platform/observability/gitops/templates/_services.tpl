{{- define "observability.dashboardSources" -}}
{{- if kindIs "map" . -}}
{{- range $key, $value := . -}}
{{- if eq $key "datasource" -}}
{{- if not (kindIs "map" $value) }}{{ fail "Dashboard datasources require approved fixed UIDs" }}{{ end -}}
{{- if not (has ($value.uid | default "") (list "metrics" "logs" "traces" "-- Grafana --")) }}{{ fail "Dashboard datasource UID is not approved" }}{{ end -}}
{{- end -}}
{{- include "observability.dashboardSources" $value -}}
{{- end -}}
{{- else if kindIs "slice" . -}}
{{- range . }}{{ include "observability.dashboardSources" . }}{{ end -}}
{{- end -}}
{{- end -}}

{{- define "observability.services" -}}
{{- $bindings := dict -}}{{- $catalog := dict -}}{{- $rules := dict -}}{{- $dashboards := dict -}}{{- $links := list -}}
{{- range .Values.catalog -}}
{{- $_ := set $catalog .approval.name . -}}
{{- $monitor := include "cloudlab.service.monitoring" . | fromJson -}}
{{- if and $monitor.enabled (ne .publication "retired") -}}
{{- $_ := set $bindings .approval.name (dict "namespace" .approval.namespace "port" $monitor.port "routes" $monitor.routes "owner" .definition.owner) -}}
{{- end -}}
{{- end -}}
{{- range $name, $input := .Values.serviceObservability -}}
{{- $entry := get $catalog $name -}}
{{- if or (not $entry) (eq $entry.publication "retired") }}{{ fail "Service observability requires a current approved catalog binding" }}{{ end -}}
{{- $seen := dict -}}{{- $seenGroups := dict -}}
{{- range $ruleName, $rule := $input.rules | default dict -}}
{{- $groups := list -}}
{{- range $group := $rule.groups -}}
{{- $groupName := printf "svc-%s-%s-%s" $name $ruleName $group.name -}}
{{- if hasKey $seenGroups $groupName }}{{ fail "Duplicate native rule group" }}{{ end -}}
{{- $_ := set $seenGroups $groupName true -}}
{{- $nativeRules := list -}}
{{- range $original := $group.rules -}}
{{- $row := deepCopy $original -}}
{{- $identity := $row.alert | default $row.record -}}
{{- if hasKey $seen $identity }}{{ fail "Duplicate native alert or recording name" }}{{ end -}}
{{- $_ := set $seen $identity true -}}
{{- if hasKey $row "record" -}}
{{- if not (hasPrefix (printf "svc_%s:" (replace "-" "_" $name)) $row.record) }}{{ fail "Recording names require their stable service prefix" }}{{ end -}}
{{- else -}}
{{- if not (hasPrefix (printf "Svc_%s_" (replace "-" "_" $name)) $row.alert) }}{{ fail "Alert names require their stable service prefix" }}{{ end -}}
{{- end -}}
{{- $labels := $row.labels | default dict -}}
{{- range $key, $_ := $labels -}}
{{- if or (has $key (list "service" "namespace" "job" "instance" "pod" "alertname" "alertstate" "receiver" "team")) (hasPrefix "cloudlab" $key) (hasPrefix "__" $key) }}{{ fail "Native rules cannot override ownership or routing labels" }}{{ end -}}
{{- end -}}
{{- if and (hasKey $labels "severity") (not (has $labels.severity (list "info" "warning" "critical"))) }}{{ fail "Native severity must use the reviewed routing vocabulary" }}{{ end -}}
{{- $_ := set $labels "service" $name -}}{{- $_ := set $labels "namespace" $entry.approval.namespace -}}
{{- if and (hasKey $row "alert") (not (hasKey $labels "severity")) }}{{ $_ := set $labels "severity" "warning" }}{{ end -}}
{{- $_ := set $row "labels" $labels -}}
{{- $annotations := $row.annotations | default dict -}}
{{- range $key := list "dashboard_url" "logs_url" -}}
{{- if hasKey $annotations $key }}{{ fail "Investigation links belong to the native owner" }}{{ end -}}
{{- end -}}
{{- if hasKey $row "alert" -}}
{{- $dashboardUID := "active-alerts" -}}
{{- if hasKey $input "dashboard" }}{{ $dashboardUID = printf "svc-%s" $name }}{{ end -}}
{{- $_ := set $annotations "dashboard_url" (printf "https://%s/d/%s" $.Values.observabilityInputs.grafanaHost $dashboardUID) -}}
{{- $_ := set $annotations "logs_url" (printf "https://%s/explore?left=%s" $.Values.observabilityInputs.grafanaHost (urlquery (toJson (dict "datasource" "logs" "queries" (list (dict "expr" (printf "{namespace=%q}" $entry.approval.namespace))))))) -}}
{{- $_ := set $row "annotations" $annotations -}}
{{- end -}}
{{- $nativeRules = append $nativeRules $row -}}
{{- end -}}
{{- $groups = append $groups (dict "name" $groupName "rules" $nativeRules) -}}
{{- end -}}
{{- $resourceName := printf "svc-%s-%s" $name $ruleName -}}
{{- if hasKey $rules $resourceName }}{{ fail "Native rule resource names collide" }}{{ end -}}
{{- $_ := set $rules $resourceName (dict "groups" $groups) -}}
{{- end -}}
{{- if hasKey $input "dashboard" -}}
{{- $board := deepCopy $input.dashboard -}}
{{- if or (ne ($board.uid | default "") (printf "svc-%s" $name)) (ne (toString $board.editable) "false") (gt (len (toJson $board)) 98304) }}{{ fail "Service dashboards require stable svc UID, editable false and at most 96KiB" }}{{ end -}}
{{- include "observability.dashboardSources" $board -}}
{{- $_ := set $dashboards (printf "svc-%s.json" $name) (toJson $board) -}}
{{- $links = append $links (dict "title" $name "type" "link" "url" (printf "/d/svc-%s" $name)) -}}
{{- end -}}
{{- end -}}
{{- dict "bindings" $bindings "rules" $rules "dashboards" $dashboards "links" $links | toJson -}}
{{- end -}}
