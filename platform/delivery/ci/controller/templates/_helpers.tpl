{{- define "cloudlab.ci.controller.normalize" -}}
{{- if not (hasKey . "controllerNormalized") }}
{{- $v := deepCopy .Values }}
{{- $registration := hasKey $v "registration" }}
{{- $component := hasKey $v "component" }}
{{- if ne $registration $component }}{{ fail "Controller registration and component belong together" }}{{- end }}
{{- if $registration }}
{{- if ne .Release.Namespace "cloudlab-ci-system" }}{{ fail "Derived controllers reconcile from the system namespace" }}{{- end }}
{{- if .Values.manageSystemNamespace }}{{ fail "Per-application controllers must not manage the system namespace" }}{{- end }}
{{- $r := $v.registration }}
{{- $app := $r.application }}
{{- $vis := $r.source.visibility }}
{{- $watch := printf "cloudlab-ci-%s-%s" $vis $app }}
{{- $ci := $r.ci }}
{{- if ne $ci.profile (printf "%s-main" $vis) }}{{ fail "Controller profile must match its source visibility" }}{{- end }}
{{- if not (kindIs "bool" $ci.jobs.test) }}{{ fail "Derived controllers require the test job decision" }}{{- end }}
{{- $publish := false }}
{{- if hasKey $ci.jobs "publish" }}{{ $publish = $ci.jobs.publish }}{{- end }}
{{- if not (kindIs "bool" $publish) }}{{ fail "Derived controllers require the publishing job decision" }}{{- end }}
{{- if and $publish (not (hasKey $r "publishing")) }}{{ fail "Publishing requires its destination block" }}{{- end }}
{{- if not (kindIs "map" ($v.images | default dict)) }}{{ fail "Derived controllers require platform images" }}{{- end }}
{{- $controller := index $v.images "controller" | default "" }}
{{- $parts := splitList "@" $controller }}
{{- if or (ne (len $parts) 2) (not (regexMatch "^[a-z0-9.-]+/cloudlab-public/ci-controller$" (index $parts 0))) (not (regexMatch "^sha256:[a-f0-9]{64}$" (index $parts 1))) }}{{ fail "Derived controllers require the qualified controller image" }}{{- end }}
{{- if ne .Values.arc.image.repository (index $parts 0) }}{{ fail "Derived controller image must match the qualified platform image" }}{{- end }}
{{- if ne .Values.arc.image.tag (printf "0.15.0@%s" (index $parts 1)) }}{{ fail "Derived controller image must match the qualified platform image" }}{{- end }}
{{- if ne .Values.arc.flags.watchSingleNamespace $watch }}{{ fail "Derived controllers must watch their application namespace" }}{{- end }}
{{- $_ := set .Values "runnerPools" (ternary 2 1 $publish) }}
{{- end }}
{{- $_ := set . "controllerNormalized" true }}
{{- end }}
{{- end }}
