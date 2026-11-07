{{- define "cloudlab.service.identity" -}}
{{- $oidc := .definition.oidc -}}
{{- $coordinates := dict "enabled" $oidc.enabled -}}
{{- if $oidc.enabled -}}
{{- $_ := set $coordinates "realm" $oidc.realm -}}
{{- $_ := set $coordinates "client" $oidc.client -}}
{{- if not $oidc.public -}}
{{- $mounted := false -}}
{{- range .definition.secrets -}}{{- if eq .name $oidc.secretReference -}}{{- $mounted = true -}}{{- end -}}{{- end -}}
{{- if or (not $mounted) (not (has $oidc.secretReference .approval.secretReferences)) -}}
{{- fail "Identity credential requires its approved scoped secret mount" -}}
{{- end -}}
{{- $_ := set $coordinates "secretReference" $oidc.secretReference -}}
{{- end -}}
{{- end -}}
{{- toJson $coordinates -}}
{{- end -}}
