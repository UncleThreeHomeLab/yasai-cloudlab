{{- define "cloudlab.service.identity" -}}
{{- $oidc := .definition.oidc -}}
{{- $coordinates := dict "enabled" $oidc.enabled -}}
{{- if hasKey $oidc "clientReference" -}}
{{- if or (hasKey .approval "composition") (ne (.approval.chartPath | default "charts/service") "charts/service") -}}
{{- fail "Identity references require the ordinary service profile" -}}
{{- end -}}
{{- $expected := dict "realm" "applications" "client" $oidc.clientReference -}}
{{- if hasKey $oidc "secretReference" -}}
{{- $_ := set $expected "secretReference" $oidc.secretReference -}}
{{- $mounted := false -}}
{{- range .definition.secrets -}}{{- if eq .name $oidc.secretReference -}}{{- $mounted = true -}}{{- end -}}{{- end -}}
{{- if or (not $mounted) (not (has $oidc.secretReference .approval.secretReferences)) -}}
{{- fail "Identity credential requires its approved scoped secret mount" -}}
{{- end -}}
{{- end -}}
{{- if ne (toJson (.approval.identityClient | default dict)) (toJson $expected) -}}
{{- fail "Identity reference differs from its protected client binding" -}}
{{- end -}}
{{- $coordinates = merge $coordinates $expected -}}
{{- else -}}
{{- if hasKey .approval "identityClient" -}}{{- fail "Identity binding is only valid for a client reference" -}}{{- end -}}
{{- if $oidc.enabled -}}
{{- $_ := set $coordinates "realm" $oidc.realm -}}
{{- $_ := set $coordinates "client" $oidc.client -}}
{{- if not $oidc.public -}}{{- $_ := set $coordinates "secretReference" $oidc.secretReference -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- toJson $coordinates -}}
{{- end -}}
