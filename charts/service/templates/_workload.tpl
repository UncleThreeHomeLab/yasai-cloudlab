{{- define "cloudlab.service.workload" -}}
{{- $v := .Values }}
{{- if and .Values.persistence.enabled (gt (int .Values.replicas) 1) }}
{{- fail "ReadWriteOnce service persistence requires one replica" }}
{{- end }}
{{- if .Values.monitoring.enabled }}
{{- fail "Monitoring requires a separately accepted dependency integration" }}
{{- end }}
{{- if and .Values.rollouts.enabled (or .Values.persistence.enabled (eq .Values.exposure.class "none")) }}
{{- fail "Rollouts require a stateless service and a Gateway API exposure" }}
{{- end }}
{{- $metrics := false }}
{{- range .Values.ports }}
{{- if and (eq .name "http-metrics") (eq (int .port) 9091) }}{{ $metrics = true }}{{- end }}
{{- end }}
{{- if and .Values.rollouts.enabled (not $metrics) }}
{{- fail "Rollouts require the per-revision release exporter on http-metrics port 9091" }}
{{- end }}
{{- if and .Values.rollouts.enabled (hasKey .Values.environment "CLOUDLAB_REVISION") }}
{{- fail "Rollouts reserve CLOUDLAB_REVISION for the pod template hash" }}
{{- end }}
{{- range .Values.secrets }}
{{- if or (hasPrefix "../" .mountPath) (hasPrefix "/var/run" .mountPath) (hasPrefix "/proc" .mountPath) }}
{{- fail "Secret mount path is reserved" }}
{{- end }}
{{- end }}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ .Values.name }}
  labels: {cloudlab.io/owner: {{ .Values.owner | quote }}}
automountServiceAccountToken: false
---
apiVersion: {{ if .Values.rollouts.enabled }}argoproj.io/v1alpha1{{ else }}apps/v1{{ end }}
kind: {{ if .Values.rollouts.enabled }}Rollout{{ else }}Deployment{{ end }}
metadata:
  name: {{ .Values.name }}
  labels: {cloudlab.io/owner: {{ .Values.owner | quote }}}
spec:
  replicas: {{ .Values.replicas }}
  revisionHistoryLimit: 2
  {{- if .Values.rollouts.enabled }}
  progressDeadlineSeconds: 600
  progressDeadlineAbort: true
  strategy:
    canary:
      stableService: {{ .Values.name }}
      canaryService: {{ .Values.name }}-canary
      maxUnavailable: 0
      maxSurge: 1
      scaleDownDelaySeconds: 30
      abortScaleDownDelaySeconds: 30
      trafficRouting:
        plugins:
          argoproj-labs/gatewayAPI:
            namespace: {{ .Release.Namespace }}
            disableInProgressLabel: true
            httpRoutes:
              - {name: {{ .Values.name }}}
              {{- range $index, $exposure := .Values.additionalExposures }}
              - {name: {{ printf "%s-extra-%d" $.Values.name $index }}}
              {{- end }}
      steps:
        - setWeight: 50
        - pause: {duration: 30s}
        - analysis:
            templates: [{templateName: {{ .Values.name }}-release}]
            args:
              - name: revision
                valueFrom: {podTemplateHashValue: Latest}
  {{- else }}
  strategy:
    {{- if .Values.persistence.enabled }}
    type: Recreate
    {{- else }}
    type: RollingUpdate
    rollingUpdate: {maxUnavailable: 0, maxSurge: 1}
    {{- end }}
  {{- end }}
  selector:
    matchLabels: {app.kubernetes.io/name: {{ .Values.name }}}
  template:
    metadata:
      {{- with .Values.artifactPolicyHash }}
      annotations:
        cloudlab.io/artifact-policy: {{ . | quote }}
      {{- end }}
      labels:
        app.kubernetes.io/name: {{ .Values.name }}
        cloudlab.io/owner: {{ .Values.owner | quote }}
        {{- if .Values.rollouts.enabled }}
        cloudlab.io/release-analysis: approved
        {{- end }}
        {{- if eq (index .Values.environment "OTEL_ENABLED" | default "") "1" }}
        cloudlab.io/telemetry: safe
        {{- end }}
    spec:
      serviceAccountName: {{ .Values.name }}
      automountServiceAccountToken: false
      {{- with .Values.imagePullSecrets }}
      imagePullSecrets: {{ . | toJson }}
      {{- end }}
      {{- if gt (int .Values.replicas) 1 }}
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: DoNotSchedule
          matchLabelKeys: [{{ if .Values.rollouts.enabled }}rollouts-pod-template-hash{{ else }}pod-template-hash{{ end }}]
          labelSelector:
            matchLabels: {app.kubernetes.io/name: {{ .Values.name }}}
      {{- end }}
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile: {type: RuntimeDefault}
      {{- if .Values.initCommand }}
      initContainers:
        - name: dependencies
          image: {{ .Values.image | quote }}
          command: {{ .Values.initCommand | toJson }}
          resources: {{ .Values.resources | toJson }}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          volumeMounts:
            - {name: temporary, mountPath: /tmp}
            - {name: dependencies, mountPath: /dependencies}
            {{- range .Values.configMaps }}
            - {name: {{ .name }}, mountPath: {{ .mountPath | quote }}, readOnly: true}
            {{- end }}
      {{- end }}
      containers:
        - name: application
          image: {{ .Values.image | quote }}
          imagePullPolicy: IfNotPresent
          command: {{ .Values.command | toJson }}
          ports:
            {{- range .Values.ports }}
            - {name: {{ .name }}, containerPort: {{ .port }}, protocol: TCP}
            {{- end }}
          startupProbe:
            httpGet: {{ .Values.health.readiness | toJson }}
            periodSeconds: 5
            failureThreshold: 60
          readinessProbe:
            httpGet: {{ .Values.health.readiness | toJson }}
            periodSeconds: 5
            timeoutSeconds: 2
          livenessProbe:
            httpGet: {{ .Values.health.liveness | toJson }}
            periodSeconds: 10
            timeoutSeconds: 2
          resources: {{ .Values.resources | toJson }}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          env:
            - {name: PYTHONDONTWRITEBYTECODE, value: '1'}
            {{- if .Values.rollouts.enabled }}
            - name: CLOUDLAB_REVISION
              valueFrom:
                fieldRef: {fieldPath: "metadata.labels['rollouts-pod-template-hash']"}
            {{- end }}
            {{- range $key, $value := .Values.environment }}
            - {name: {{ $key }}, value: {{ $value | quote }}}
            {{- end }}
          volumeMounts:
            - {name: temporary, mountPath: /tmp}
            {{- if .Values.initCommand }}
            - {name: dependencies, mountPath: /dependencies, readOnly: true}
            {{- end }}
            {{- range .Values.secrets }}
            - {name: {{ .name }}, mountPath: {{ .mountPath | quote }}, readOnly: true}
            {{- end }}
            {{- range .Values.configMaps }}
            - {name: {{ .name }}, mountPath: {{ .mountPath | quote }}, readOnly: true}
            {{- end }}
            {{- if .Values.persistence.enabled }}
            - {name: data, mountPath: {{ .Values.persistence.mountPath | quote }}}
            {{- end }}
      volumes:
        - {name: temporary, emptyDir: {sizeLimit: 64Mi}}
        {{- if .Values.initCommand }}
        - {name: dependencies, emptyDir: {sizeLimit: 128Mi}}
        {{- end }}
        {{- range .Values.secrets }}
        - name: {{ .name }}
          secret: {secretName: {{ .name }}, defaultMode: 288}
        {{- end }}
        {{- range .Values.configMaps }}
        - name: {{ .name }}
          configMap: {name: {{ .name }}}
        {{- end }}
        {{- if .Values.persistence.enabled }}
        - {name: data, persistentVolumeClaim: {claimName: {{ .Values.name }}}}
        {{- end }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ .Values.name }}
  labels: {app.kubernetes.io/name: {{ .Values.name }}}
spec:
  type: ClusterIP
  selector: {app.kubernetes.io/name: {{ .Values.name }}}
  ports:
    {{- range .Values.ports }}
    - {name: {{ .name }}, port: {{ .port }}, targetPort: {{ .name }}, protocol: TCP}
    {{- end }}
{{- if .Values.rollouts.enabled }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ .Values.name }}-canary
spec:
  type: ClusterIP
  selector: {app.kubernetes.io/name: {{ .Values.name }}}
  ports:
    {{- range .Values.ports }}
    - {name: {{ .name }}, port: {{ .port }}, targetPort: {{ .name }}, protocol: TCP}
    {{- end }}
{{- end }}
{{- if .Values.persistence.enabled }}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ .Values.name }}
  annotations:
    argocd.argoproj.io/sync-options: Prune=false,Delete=false
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: cloudlab-data
  resources:
    requests: {storage: {{ .Values.persistence.size }}}
{{- end }}

{{- end }}
