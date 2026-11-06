{{- define "observability.handoffBaselineDigest" -}}
{{- toJson . | sha256sum -}}
{{- end -}}

{{- define "observability.activationQualification" -}}
{{- $pointer := .Values.nativeSource.activationQualification | default "" -}}
{{- $registry := .Files.Get "handoff-profiles.json" | fromJson -}}
{{- $accepted := get $registry.acceptedArtifacts "handoff" | default dict -}}
{{- $scope := get $accepted "scope" | default dict -}}
{{- $artifacts := get $accepted "artifactDigests" | default dict -}}
{{- if or (not (kindIs "string" $pointer)) (not (regexMatch "^[a-f0-9]{64}$" $pointer)) (eq $pointer (repeat 64 "0")) (ne (get $accepted "profile") "handoff") (ne (get $accepted "version") "cloudlab-observability-qualification/v1") (ne (len $scope) 1) (ne (get $scope "kind") "full-entrypoint-integration") (ne (get $artifacts "handoff-evidence.json") $pointer) }}{{ fail "Native activation requires matching reviewed full C2 entrypoint integration" }}{{ end -}}
{{- end -}}

{{- define "observability.handoffApplications" -}}
{{- $input := .Values.ownershipHandoff -}}
{{- $registry := .Files.Get "handoff-profiles.json" | fromJson -}}
{{- if ne (len $input.qualifications) (len $registry.requiredProfiles) }}{{ fail "Handoff requires every fixed qualification profile" }}{{ end -}}
{{- range $name, $version := $registry.requiredProfiles -}}
{{- $reference := get $input.qualifications $name -}}
{{- $accepted := get $registry.acceptedArtifacts $name -}}
{{- if or (not $accepted) (ne $reference.version $version) (ne (toJson $reference) (toJson $accepted)) }}{{ fail "Handoff profile lacks matching reviewed native qualification" }}{{ end -}}
{{- end -}}
{{- $scope := $input.qualifications.handoff.scope -}}
{{- if eq $scope.kind "mechanism-rehearsal" -}}
{{- if ne (sha256sum $input.targetClusterUID) $scope.targetClusterUIDSHA256 }}{{ fail "Mechanism rehearsal target differs from reviewed cluster commitment" }}{{ end -}}
{{- else if ne $scope.kind "full-entrypoint-integration" }}{{ fail "Handoff qualification scope is unsupported" }}{{ end -}}
{{- if gt (len (toJson $input.baselineApplications)) 196608 }}{{ fail "Handoff baseline exceeds 192KiB" }}{{ end -}}
{{- $phase := $input.phase -}}
{{- if eq $phase "native" }}{{ include "observability.activationQualification" . }}{{ end -}}
{{- $storage := index $registry.storageProfiles $input.approvedStorageTarget -}}
{{- if not $storage }}{{ fail "Handoff storage target lacks fixed reviewed profile" }}{{ end -}}
{{- $maintenance := has $phase (list "maintenance" "persistent-maintenance") -}}
{{- $persistent := has $phase (list "persistent-maintenance" "persistent-normal") -}}
{{- $native := has $phase (list "native-paused" "native") -}}
{{- $canonical := dict -}}
{{- range $document := splitList "\n---" (include "observability.nativeApplications" .) -}}
{{- $application := fromYaml (trimPrefix "---" $document) -}}
{{- if $application.kind }}{{ $_ := set $canonical $application.metadata.name $application }}{{ end -}}
{{- end -}}
{{- $digest := include "observability.handoffBaselineDigest" $input.baselineApplications -}}
{{- $baselineRevision := (get $input.baselineApplications "cloudlab-observability").spec.source.targetRevision -}}
{{- range $component := list "configuration" "prometheus" "loki" "tempo" "alloy" "kiali" -}}
{{- $name := ternary "cloudlab-observability" (printf "cloudlab-%s" $component) (eq $component "configuration") -}}
{{- $baseline := get $input.baselineApplications $name -}}
{{- $source := $baseline.spec.source -}}
{{- if ne $source.targetRevision $baselineRevision }}{{ fail "Handoff baselines require one reviewed immutable public revision" }}{{ end -}}
{{- if hasKey ($source.helm.valuesObject | default dict) "ownershipHandoffInternal" }}{{ fail "Handoff baseline cannot supply adapter controls" }}{{ end -}}
{{- $path := printf "platform/observability%s" (ternary "" (printf "/%s" $component) (eq $component "configuration")) -}}
{{- if or (ne $baseline.metadata.name $name) (ne $source.repoURL $.Values.nativeSource.repository) (ne $source.path $path) (ne $source.helm.releaseName $name) }}{{ fail "Handoff baseline changed canonical component source identity" }}{{ end -}}
{{- if and (ne $component "configuration") (ne (toJson $source.helm.valueFiles) (toJson (list "values.json"))) }}{{ fail "Handoff baseline changed component value files" }}{{ end -}}
{{- if and (eq $component "configuration") (hasKey $source.helm "valueFiles") }}{{ fail "Configuration baseline cannot select value files" }}{{ end -}}
{{- $application := deepCopy $baseline -}}
{{- if $native }}{{ $application = deepCopy (get $canonical $name) }}{{ end -}}
{{- if not (hasKey $application.metadata "annotations") }}{{ $_ := set $application.metadata "annotations" dict }}{{ end -}}
{{- $_ := set $application.metadata.annotations "cloudlab.io/observability-handoff-operation" $input.operationId -}}
{{- $_ := set $application.metadata.annotations "cloudlab.io/observability-handoff-phase" $phase -}}
{{- $_ := set $application.metadata.annotations "cloudlab.io/observability-handoff-baseline" $digest -}}
{{- $_ := set $application.metadata.annotations "cloudlab.io/observability-handoff-target-cluster-uid" $input.targetClusterUID -}}
{{- $paused := eq $phase "native-paused" -}}
{{- $_ := set $application.metadata.annotations "argocd.argoproj.io/skip-reconcile" (printf "%t" $paused) -}}
{{- $_ := set $application.spec.syncPolicy "automated" (dict "enabled" (eq $phase "native") "prune" (eq $phase "native") "selfHeal" (eq $phase "native") "allowEmpty" false) -}}
{{- if not $native -}}
{{- $values := $application.spec.source.helm.valuesObject -}}
{{- if and (has $component (list "configuration" "prometheus")) (not (kindIs "map" $values)) }}{{ fail "Handoff configuration and Prometheus adapters require explicit baseline values" }}{{ end -}}
{{- if eq $component "configuration" -}}
{{- $_ := set $application.spec.source "targetRevision" $.Values.nativeSource.revision -}}
{{- $control := dict "version" $input.version "phase" $phase "operationId" $input.operationId "baselineDigest" $digest -}}
{{- if $input.quotaIncrease }}{{ $_ := set $control "quotaIncrease" $input.quotaIncrease }}{{ end -}}
{{- $_ := set $values "ownershipHandoffInternal" $control -}}
{{- else if and (eq $component "prometheus") (or $maintenance $persistent) -}}
{{- $_ := set $application.spec.source "targetRevision" $.Values.nativeSource.revision -}}
{{- $alertmanager := $values | dig "kube-prometheus-stack" "alertmanager" dict -}}
{{- if or (not (kindIs "map" $alertmanager.config)) (not $alertmanager.config.receivers) $alertmanager.stringConfig $alertmanager.tplConfig (dig "alertmanagerSpec" "useExistingSecret" false $alertmanager) }}{{ fail "Handoff baseline requires explicit original Alertmanager configuration without alternate configuration sources" }}{{ end -}}
{{- $spec := $alertmanager.alertmanagerSpec | default dict -}}
{{- if or (and $spec.configSecret (ne (toString $spec.configSecret) "alertmanager-cloudlab")) $spec.alertmanagerConfiguration $spec.alertmanagerConfigSelector $spec.alertmanagerConfigNamespaceSelector }}{{ fail "Handoff requires the canonical generated Alertmanager Secret without explicit configuration sources or selectors" }}{{ end -}}
{{- if $maintenance -}}
{{- $receivers := list -}}
{{- range $receiver := $alertmanager.config.receivers }}{{ $receivers = append $receivers (dict "name" $receiver.name) }}{{ end -}}
{{- $_ := set $alertmanager.config "receivers" $receivers -}}
{{- end -}}
{{- if $persistent -}}
{{- $_ := set (get $values "kube-prometheus-stack") "cloudlabNativeLifecycle" true -}}
{{- $_ := set $spec "persistentVolumeClaimRetentionPolicy" (deepCopy $storage.persistentVolumeClaimRetentionPolicy) -}}
{{- $claimSpec := dict "storageClassName" $storage.storageClassName "accessModes" $storage.accessModes "volumeMode" $storage.volumeMode "resources" (dict "requests" (dict "storage" $storage.storage)) -}}
{{- $claim := dict "metadata" (dict "annotations" (dict "argocd.argoproj.io/sync-options" "Prune=false,Delete=false")) "spec" $claimSpec -}}
{{- $_ := set $spec "storage" (dict "volumeClaimTemplate" $claim) -}}
{{- $_ := set $alertmanager "alertmanagerSpec" $spec -}}
{{- end -}}
{{- $_ := set (get $values "kube-prometheus-stack") "alertmanager" $alertmanager -}}
{{- end -}}
{{- end }}
---
{{ toYaml $application }}
{{- end -}}
{{- end -}}
