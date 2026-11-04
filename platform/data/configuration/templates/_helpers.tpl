{{- define "cloudlab.data.sql" -}}
{{- if or (not (regexMatch "^[a-z][a-z0-9_]{0,62}$" .)) (hasPrefix "pg_" .) (has . (list "postgres" "template0" "template1")) }}{{ fail "Invalid or reserved data SQL identifier" }}{{- end }}
{{- end }}

{{- define "cloudlab.data.normalize" -}}
{{- if not (hasKey . "dataSettings") }}
{{- $v := deepCopy .Values }}
{{- if $v.sharedInputs }}
{{- if or $v.serviceRequests $v.serviceConsumers }}{{ fail "Native data requests and consumers must derive only from the complete catalog" }}{{- end }}
{{- $_ := set $v "s3Host" (printf "s3.internal.%s" $v.zone) }}
{{- range $value := list $v.database $v.applicationRole $v.migrationRole $v.backupRole $v.identity.database $v.identity.role }}{{ include "cloudlab.data.sql" $value }}{{- end }}
{{- if ne (len (uniq (list $v.applicationRole $v.migrationRole $v.backupRole))) 3 }}{{ fail "Data platform roles must differ" }}{{- end }}
{{- $protectedRoles := list $v.applicationRole $v.migrationRole $v.backupRole }}
{{- $protectedDatabases := list $v.database }}
{{- if $v.identity.enabled }}
{{- if or (eq $v.identity.database $v.database) (has $v.identity.role $protectedRoles) }}{{ fail "Identity requires its dedicated data scope" }}{{- end }}
{{- $protectedRoles = append $protectedRoles $v.identity.role }}
{{- $protectedDatabases = append $protectedDatabases $v.identity.database }}
{{- end }}
{{- $services := dict }}{{- $databases := dict }}{{- $roles := dict }}{{- $buckets := dict }}{{- $consumers := dict }}{{- $requests := list }}
{{- range $entry := $v.catalog }}
{{- $name := $entry.approval.name }}{{- $namespace := printf "cloudlab-app-%s" $name }}
{{- if or (hasKey $services $name) (ne $entry.approval.namespace $namespace) }}{{ fail "Native data catalog has duplicate or mismatched service scopes" }}{{- end }}
{{- $_ := set $services $name true }}
{{- $row := dict "service" $name "namespace" $namespace }}
{{- range $kind, $request := $entry.definition.data }}
{{- $scope := get $v.dataApprovals $request.credentialReference }}
{{- if or (not $scope) (ne $scope.kind $kind) (ne $scope.service $name) (ne $scope.name $request.name) (ne $request.retention "retain") }}{{ fail "Native data request requires its exact administrator approval" }}{{- end }}
{{- if eq $kind "database" }}
{{- if or (not (hasKey $scope "applicationRole")) (not (hasKey $scope "migrationRole")) }}{{ fail "Native database approvals require both role names" }}{{- end }}
{{- range $value := list $request.name $scope.applicationRole $scope.migrationRole }}{{ include "cloudlab.data.sql" $value }}{{- end }}
{{- if or (eq $scope.applicationRole $scope.migrationRole) (hasKey $databases $request.name) (hasKey $roles $scope.applicationRole) (hasKey $roles $scope.migrationRole) }}{{ fail "Native data database or role scopes overlap" }}{{- end }}
{{- $_ := set $databases $request.name true }}{{- $_ := set $roles $scope.applicationRole true }}{{- $_ := set $roles $scope.migrationRole true }}{{- $_ := set $consumers $namespace true }}
{{- $original := and (eq $name "notes") (eq $request.name $v.database) (eq $scope.applicationRole $v.applicationRole) (eq $scope.migrationRole $v.migrationRole) (eq $scope.item "cnpg-notes-production") (eq $scope.migrationItem "cnpg-notes-migration") }}
{{- if or (and (eq $name "notes") (not $original)) (and $v.identity.enabled (eq $name "keycloak")) }}{{ fail "Native service database collides with a fixed platform resource" }}{{- end }}
{{- if and (not $original) (or (has $request.name $protectedDatabases) (has $scope.applicationRole $protectedRoles) (has $scope.migrationRole $protectedRoles)) }}{{ fail "Native service data overlaps a protected platform identity" }}{{- end }}
{{- if not $original }}{{- $_ := set $row "database" (dict "name" $request.name "applicationRole" $scope.applicationRole "migrationRole" $scope.migrationRole "applicationItem" $scope.item "migrationItem" $scope.migrationItem) }}{{- end }}
{{- else }}
{{- if hasKey $buckets $request.name }}{{ fail "Native service buckets overlap" }}{{- end }}
{{- $_ := set $buckets $request.name true }}
{{- $original := and (eq $name "notes") (eq $request.name $v.bucket) (eq $scope.item "s3-notes-production") }}
{{- if or (and (eq $name "notes") (not $original)) (has $name (list "data-admin" "admin" "app")) }}{{ fail "Native service bucket collides with a fixed platform identity or credential prefix" }}{{- end }}
{{- if and (eq $request.name $v.bucket) (not $original) }}{{ fail "Native service bucket overlaps the platform owner" }}{{- end }}
{{- if not $original }}{{- $_ := set $row "bucket" (dict "name" $request.name "item" $scope.item) }}{{- end }}
{{- end }}
{{- end }}
{{- if gt (len $row) 2 }}{{- $requests = append $requests $row }}{{- end }}
{{- end }}
{{- if gt (len $requests) 8 }}{{ fail "Native data exceeds the retained service request limit" }}{{- end }}
{{- $_ := set $v "serviceRequests" $requests }}
{{- $_ := set $v "serviceConsumers" (keys $consumers | sortAlpha) }}
{{- end }}
{{- $_ := set . "dataSettings" $v }}
{{- end }}
{{- end }}
