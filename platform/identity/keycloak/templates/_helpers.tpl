{{- define "identity.protocol-paths" -}}
{{- range $realm := list "platform" "applications" }}
- {{ printf "/realms/%s/.well-known/openid-configuration" $realm | quote }}
{{- range $endpoint := list "auth" "token" "certs" "userinfo" "logout" "logout/logout-confirm" "revoke" "introspect" "login-status-iframe.html" "login-status-iframe.html/init" "3p-cookies/step1.html" "3p-cookies/step2.html" }}
- {{ printf "/realms/%s/protocol/openid-connect/%s" $realm $endpoint | quote }}
{{- end }}
{{- range $action := list "authenticate" "required-action" "registration" "reset-credentials" "restart" "action-token" }}
- {{ printf "/realms/%s/login-actions/%s" $realm $action | quote }}
{{- end }}
{{- end }}
{{- end }}

{{- define "identity.pod" }}
serviceAccountName: identity-writer
restartPolicy: Never
activeDeadlineSeconds: 210
terminationGracePeriodSeconds: 20
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  seccompProfile: {type: RuntimeDefault}
initContainers:
  - name: validate-and-lock
    image: {{ (.Files.Get "artifact.lock.json" | fromJson).images.python | quote }}
    command: [python, -c]
    args:
      - >-
        import sys; sys.path.insert(0,'/code');
        from lease import acquire; from configuration import prepare, prepare_master, prepare_primary, prepare_removal, removal_inventory;
        {{- if .Values.operation }}
        prepare_removal('/imports', {{ .Values.operation.realm | quote }}, {{ .Values.operation.client | quote }}, '/private');
        {{- else }}
        prepare('/imports', {{ .Values.loginHost | quote }}, {{ ternary "'/private'" "None" .Values.privateStateEnabled }}, {{ ternary "'/credentials'" "None" .Values.bootstrapMode }}, {{ ternary "'/health-credentials'" "None" .Values.bootstrapMode }}, primary={{ ternary "True" "False" .Values.primaryAdminEnabled }});
        {{- if .Values.bootstrapMode }}
        prepare_master('/imports', {{ .Values.adminHost | quote }}, '/bootstrap');
        {{- if .Values.primaryAdminEnabled }}
        prepare_primary('/imports', '/primary', '/bootstrap', {{ .Values.adminHost | quote }});
        {{- end }}
        {{- end }}
        {{- end }}
        acquire();
        {{- if .Values.operation }}
        removal_inventory('/imports', {{ .Values.operation.realm | quote }}, {{ .Values.operation.client | quote }}, {{ .Values.adminHost | quote }})
        {{- end }}
    env:
      - name: POD_UID
        valueFrom: {fieldRef: {fieldPath: metadata.uid}}
    securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
    resources:
      requests: {cpu: 10m, memory: 32Mi}
      limits: {cpu: 100m, memory: 64Mi}
    volumeMounts:
      - {name: code, mountPath: /code, readOnly: true}
      - {name: imports, mountPath: /imports}
      {{- if or .Values.bootstrapMode (not (empty .Values.operation)) }}
      - {name: credentials, mountPath: /credentials, readOnly: true}
      {{- end }}
      {{- if .Values.bootstrapMode }}
      - {name: health-credentials, mountPath: /health-credentials, readOnly: true}
      - {name: bootstrap, mountPath: /bootstrap, readOnly: true}
      {{- if .Values.primaryAdminEnabled }}
      - {name: primary, mountPath: /primary, readOnly: true}
      {{- end }}
      {{- end }}
      {{- if .Values.privateStateEnabled }}
      - {name: private, mountPath: /private, readOnly: true}
      {{- end }}
containers:
  - name: config-cli
    image: {{ (.Files.Get "artifact.lock.json" | fromJson).images.config_cli | quote }}
    command: [/bin/sh, -ec]
    args:
      - |
        {{- if .Values.operation }}
        if test -f /imports/skip; then echo 'Retired client already absent; no realm changes'; exit 0; fi
        export KEYCLOAK_LOGINREALM={{ .Values.operation.realm | quote }}
        export KEYCLOAK_CLIENTID=realm-writer
        export KEYCLOAK_CLIENTSECRET="$(cat /credentials/${KEYCLOAK_LOGINREALM}_client_secret)"
        for phase in seed remove; do
          managed=no-delete
          if test "$phase" = remove; then managed=full; fi
          export IMPORT_FILES_LOCATIONS="/imports/$phase.json"
          java -jar /app/keycloak-config-cli.jar --spring.config.additional-location=file:/code/config-cli.properties --import.cache.key={{ printf "remove-%s-%s" .Values.operation.realm .Values.operation.client | quote }} --import.managed.client="$managed" >/tmp/result 2>&1 || { echo 'Scoped client removal failed; private diagnostics withheld'; exit 1; }
        done
        echo 'Scoped client removal completed; unrelated objects preserved'
        {{- else }}
        {{- if .Values.bootstrapMode }}
        export KEYCLOAK_USER="$(cat /bootstrap/username)"
        export KEYCLOAK_PASSWORD="$(cat /bootstrap/password)"
        export KEYCLOAK_GRANTTYPE=password
        export KEYCLOAK_LOGINREALM=master
        export KEYCLOAK_CLIENTID=admin-cli
        export IMPORT_FILES_LOCATIONS=/imports/master-bootstrap.json
        # Changing master's frontend URL invalidates its cached bootstrap token.
        # One fresh CLI process completes the identical scoped input after that transition.
        for attempt in 1 2; do
          if java -jar /app/keycloak-config-cli.jar --spring.config.additional-location=file:/code/config-cli.properties {{ if .Values.primaryAdminEnabled }}--import.remote-state.enabled=false --import.cache.key=primary{{ end }} >/tmp/result 2>&1; then break; fi
          if test "$attempt" = 2; then echo 'Private master bootstrap failed; diagnostics withheld'; exit 1; fi
          echo 'Retrying private master bootstrap with a fresh token'
        done
        {{- if .Values.primaryAdminEnabled }}
        export IMPORT_FILES_LOCATIONS=/imports/master-bootstrap.steady.json
        java -jar /app/keycloak-config-cli.jar --spring.config.additional-location=file:/code/config-cli.properties --import.remote-state.enabled=false --import.cache.key=primary >/tmp/result 2>&1 || { echo 'Private master canonical reconciliation failed; diagnostics withheld'; exit 1; }
        {{- end }}
        {{- end }}
        for realm in platform applications; do
          {{- if not .Values.bootstrapMode }}
          export KEYCLOAK_LOGINREALM="$realm"
          export KEYCLOAK_CLIENTID=realm-writer
          export KEYCLOAK_CLIENTSECRET="$(cat /credentials/${realm}_client_secret)"
          {{- end }}
          export IMPORT_FILES_LOCATIONS="/imports/$realm.json"
          java -jar /app/keycloak-config-cli.jar --spring.config.additional-location=file:/code/config-cli.properties {{ if .Values.primaryAdminEnabled }}--import.remote-state.enabled=false --import.cache.key=primary{{ end }} >/tmp/result 2>&1 || { echo 'Scoped identity reconciliation failed; private diagnostics withheld'; exit 1; }
          {{- if .Values.primaryAdminEnabled }}
          if test "$realm" = platform; then
            export IMPORT_FILES_LOCATIONS=/imports/platform.steady.json
            java -jar /app/keycloak-config-cli.jar --spring.config.additional-location=file:/code/config-cli.properties --import.remote-state.enabled=false --import.cache.key=primary >/tmp/result 2>&1 || { echo 'Primary canonical reconciliation failed; diagnostics withheld'; exit 1; }
          fi
          {{- end }}
        done
        echo 'Scoped identity reconciliation completed'
        {{- end }}
    env:
      - {name: KEYCLOAK_URL, value: {{ printf "https://%s" .Values.adminHost | quote }}}
      - {name: KEYCLOAK_GRANTTYPE, value: client_credentials}
      - {name: KEYCLOAK_SKIPSERVERINFO, value: 'true'}
    securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
    resources:
      requests: {cpu: 100m, memory: 256Mi}
      limits: {cpu: 500m, memory: 512Mi}
    volumeMounts:
      - {name: code, mountPath: /code, readOnly: true}
      - {name: imports, mountPath: /imports, readOnly: true}
      - {name: credentials, mountPath: /credentials, readOnly: true}
      {{- if .Values.bootstrapMode }}
      - {name: bootstrap, mountPath: /bootstrap, readOnly: true}
      {{- end }}
      - {name: temporary, mountPath: /tmp}
volumes:
  - {name: code, configMap: {name: identity-writer-code}}
  - {name: imports, emptyDir: {medium: Memory, sizeLimit: 16Mi}}
  - {name: temporary, emptyDir: {medium: Memory, sizeLimit: 16Mi}}
  - {name: credentials, secret: {secretName: keycloak-realm-writers, defaultMode: 0440}}
  {{- if .Values.bootstrapMode }}
  - {name: bootstrap, secret: {secretName: keycloak-bootstrap-admin, defaultMode: 0440}}
  - name: health-credentials
    secret:
      secretName: keycloak-realm-health
      defaultMode: 0440
      items:
        - {key: platform_client_secret, path: platform_health_secret}
        - {key: applications_client_secret, path: applications_health_secret}
  {{- end }}
  {{- if .Values.primaryAdminEnabled }}
  - {name: primary, secret: {secretName: keycloak-primary-admin, defaultMode: 0440}}
  {{- end }}
  {{- if .Values.privateStateEnabled }}
  - name: private
    projected:
      defaultMode: 0440
      sources:
        - configMap:
            name: identity-private-state
            items: [{key: desired_state, path: desired_state}, {key: revocations, path: revocations}]
        - secret:
            name: keycloak-client-secrets
            items: [{key: client_secrets, path: client_secrets}]
  {{- end }}
{{- end }}
