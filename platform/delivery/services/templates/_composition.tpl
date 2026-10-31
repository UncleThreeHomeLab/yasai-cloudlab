{{- define "cloudlab.composition.images" -}}
{{- $result := dict -}}
{{- range $name, $path := .composition.imageValues -}}
{{- $image := index $.composition.images $name -}}
{{- if and $.artifact (has $name ($.artifact.components | default list)) -}}
{{- $image = printf "%s@{{ index .components %q }}" $.artifact.repository $name -}}
{{- end -}}
{{- $parts := splitList "." $path -}}
{{- $parent := $result -}}
{{- range initial $parts -}}
{{- if not (hasKey $parent .) }}{{ $_ := set $parent . dict }}{{ end -}}
{{- $parent = index $parent . -}}
{{- end -}}
{{- $_ := set $parent (last $parts) (dict "repository" (first (splitList "@" $image)) "digest" (last (splitList "@" $image))) -}}
{{- end -}}
{{- $result | toJson -}}
{{- end -}}

{{- define "cloudlab.composition.profiles" -}}
{{- $profiles := deepCopy .workloads -}}
{{- range $profiles -}}
{{- $spec := .podSpec -}}
{{- range $key, $value := dict "restartPolicy" "Always" "dnsPolicy" "ClusterFirst" "schedulerName" "default-scheduler" "serviceAccountName" "default" "terminationGracePeriodSeconds" 30 -}}
{{- if not (hasKey $spec $key) }}{{ $_ := set $spec $key $value }}{{ end -}}
{{- end -}}
{{- range $volume := $spec.volumes -}}
{{- range $kind := list "secret" "configMap" -}}
{{- if hasKey $volume $kind -}}
{{- if not (hasKey (index $volume $kind) "defaultMode") }}{{ $_ := set (index $volume $kind) "defaultMode" 420 }}{{ end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- range $container := concat $spec.containers ($spec.initContainers | default list) -}}
{{- range $container.ports -}}
{{- if not (hasKey . "protocol") }}{{ $_ := set . "protocol" "TCP" }}{{ end -}}
{{- end -}}
{{- range $key, $value := dict "imagePullPolicy" "IfNotPresent" "terminationMessagePath" "/dev/termination-log" "terminationMessagePolicy" "File" -}}
{{- if not (hasKey $container $key) }}{{ $_ := set $container $key $value }}{{ end -}}
{{- end -}}
{{- range $key := list "readinessProbe" "livenessProbe" "startupProbe" -}}
{{- if hasKey $container $key -}}
{{- $probe := index $container $key -}}
{{- range $field, $value := dict "periodSeconds" 10 "timeoutSeconds" 1 "successThreshold" 1 "failureThreshold" 3 -}}
{{- if not (hasKey $probe $field) }}{{ $_ := set $probe $field $value }}{{ end -}}
{{- end -}}
{{- if hasKey $probe "httpGet" -}}
{{- if not (hasKey $probe.httpGet "path") }}{{ $_ := set $probe.httpGet "path" "/" }}{{ end -}}
{{- if not (hasKey $probe.httpGet "scheme") }}{{ $_ := set $probe.httpGet "scheme" "HTTP" }}{{ end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $profiles | toJson -}}
{{- end -}}
