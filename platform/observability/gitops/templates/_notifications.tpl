{{- define "observability.notificationSecret" -}}
{{- $_ := set .secrets .reference.name true -}}
{{- printf "/etc/alertmanager/secrets/%s/%s" .reference.name .reference.key -}}
{{- end -}}

{{- define "observability.notifications" -}}
{{- $input := .Values.platformNotifications -}}
{{- if lt (int $input.repeatIntervalSeconds) (int $input.groupIntervalSeconds) }}{{ fail "Notification repeat interval cannot be shorter than its group interval" }}{{ end -}}
{{- $secrets := dict -}}
{{- $receivers := list (dict "name" "unconfigured") -}}
{{- $routes := list -}}
{{- $fallback := "unconfigured" -}}
{{- $catalog := dict -}}
{{- range .Values.catalog }}{{ $_ := set $catalog .definition.name . }}{{ end -}}
{{- if not $input.enabled -}}
{{- if or $input.fallbackReceiver $input.receivers $input.subscriptions }}{{ fail "Disabled notification delivery cannot contain destinations or subscriptions" }}{{ end -}}
{{- else -}}
{{- $receivers = list -}}
{{- $known := dict -}}
{{- range $receiver := $input.receivers -}}
{{- if hasKey $known $receiver.name }}{{ fail "Notification receiver names must be unique" }}{{ end -}}
{{- $_ := set $known $receiver.name true -}}
{{- $native := dict "name" $receiver.name -}}
{{- if hasKey $receiver "email" -}}
{{- $email := $receiver.email -}}
{{- $delivery := dict "to" $email.to "from" $email.from "smarthost" (printf "%s:%d" $email.host (int $email.port)) "require_tls" true "send_resolved" true -}}
{{- if hasKey $email "username" -}}
{{- $_ := set $delivery "auth_username" $email.username -}}
{{- $_ := set $delivery "auth_password_file" (include "observability.notificationSecret" (dict "reference" $email.passwordSecretRef "secrets" $secrets)) -}}
{{- end -}}
{{- if hasKey $email "caSecretRef" -}}
{{- $_ := set $delivery "tls_config" (dict "ca_file" (include "observability.notificationSecret" (dict "reference" $email.caSecretRef "secrets" $secrets))) -}}
{{- end -}}
{{- $_ := set $native "email_configs" (list $delivery) -}}
{{- else -}}
{{- $webhook := $receiver.webhook -}}
{{- $target := $webhook.target -}}
{{- if not (hasKey $catalog $target.service) }}{{ fail "Notification webhook requires an approved service" }}{{ end -}}
{{- $service := index $catalog $target.service -}}
{{- if or (eq $service.publication "retired") (ne ($service.approval.chartPath | default "") "charts/service") (hasKey $service.approval "composition") }}{{ fail "Notification webhook supports only active ordinary service backends" }}{{ end -}}
{{- $ports := list -}}
{{- range $service.definition.ports -}}
{{- if eq .name $target.port -}}
{{- if ne (.protocol | default "TCP") "TCP" }}{{ fail "Notification webhook requires a TCP service port" }}{{ end -}}
{{- $ports = append $ports .port -}}
{{- end -}}
{{- end -}}
{{- if ne (len $ports) 1 }}{{ fail "Notification webhook requires one approved named port" }}{{ end -}}
{{- $scheme := ternary "https" "http" (eq $webhook.authentication.mode "bearer") -}}
{{- $delivery := dict "url" (printf "%s://%s.%s.svc:%d%s" $scheme $service.definition.name $service.approval.namespace (int (first $ports)) $target.path) "send_resolved" true -}}
{{- $http := dict "follow_redirects" false -}}
{{- if eq $webhook.authentication.mode "bearer" -}}
{{- $_ := set $http "authorization" (dict "type" "Bearer" "credentials_file" (include "observability.notificationSecret" (dict "reference" $webhook.authentication.secretRef "secrets" $secrets))) -}}
{{- if hasKey $webhook "caSecretRef" -}}
{{- $_ := set $http "tls_config" (dict "ca_file" (include "observability.notificationSecret" (dict "reference" $webhook.caSecretRef "secrets" $secrets))) -}}
{{- end -}}
{{- end -}}
{{- $_ := set $delivery "http_config" $http -}}
{{- $_ := set $native "webhook_configs" (list $delivery) -}}
{{- end -}}
{{- $receivers = append $receivers $native -}}
{{- end -}}
{{- if not (hasKey $known $input.fallbackReceiver) }}{{ fail "Enabled notification delivery requires a declared fallback receiver" }}{{ end -}}
{{- $fallback = $input.fallbackReceiver -}}
{{- $subscriptions := dict -}}
{{- range $subscription := $input.subscriptions -}}
{{- if or (not (hasKey $catalog $subscription.service)) (hasKey $subscriptions $subscription.service) }}{{ fail "Notification subscriptions require distinct approved services" }}{{ end -}}
{{- if eq (index $catalog $subscription.service).publication "retired" }}{{ fail "Retired services cannot subscribe to notifications" }}{{ end -}}
{{- $_ := set $subscriptions $subscription.service true -}}
{{- range $receiver := $subscription.receivers -}}
{{- if not (hasKey $known $receiver) }}{{ fail "Notification subscription names an unknown receiver" }}{{ end -}}
{{- $routes = append $routes (dict "receiver" $receiver "continue" true "matchers" (list (printf "service=\"%s\"" $subscription.service) (printf "severity=~\"%s\"" (join "|" $subscription.severities)))) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $route := dict "receiver" $fallback "routes" $routes "group_by" (list "alertname" "service" "severity") "group_wait" (printf "%ds" (int $input.groupWaitSeconds)) "group_interval" (printf "%ds" (int $input.groupIntervalSeconds)) "repeat_interval" (printf "%ds" (int $input.repeatIntervalSeconds)) -}}
{{- toYaml (dict "config" (dict "global" (dict "resolve_timeout" "1m") "route" $route "receivers" $receivers) "secrets" (keys $secrets | sortAlpha)) -}}
{{- end -}}
