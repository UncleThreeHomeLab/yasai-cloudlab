{{- define "storage.config.loki" -}}
{
  "apiVersion": "v1",
  "kind": "ConfigMap",
  "metadata": {
    "name": "obs-storage-{{ .Values.operationId }}-loki-config",
    "namespace": "obs-storage-{{ .Values.operationId }}",
    "labels": {
      "helm.sh/chart": "loki-7.3.0",
      "app.kubernetes.io/name": "loki",
      "app.kubernetes.io/instance": "cloudlab-loki",
      "app.kubernetes.io/version": "3.6.11",
      "cloudlab.io/owner": "observability-lifecycle-proof",
      "cloudlab.io/storage-proof": "{{ .Values.operationId }}"
    }
  },
  "data": {
    "config.yaml": "analytics:\n  reporting_enabled: false\nauth_enabled: false\nbloom_build:\n  builder:\n    planner_address: ''\n  enabled: false\nbloom_gateway:\n  client:\n    addresses: ''\n  enabled: false\ncommon:\n  compactor_grpc_address: obs-storage-{{ .Values.operationId }}-loki.obs-storage-{{ .Values.operationId }}.svc.cluster.local:9095\n  path_prefix: /var/loki\n  replication_factor: 1\n  storage:\n    filesystem:\n      chunks_directory: /var/loki/chunks\n      rules_directory: /var/loki/rules\ncompactor:\n  compaction_interval: 10m\n  delete_request_store: filesystem\n  retention_delete_delay: 15m\n  retention_enabled: true\n  working_directory: /var/loki/compactor\nfrontend:\n  scheduler_address: ''\n  tail_proxy_url: ''\nfrontend_worker:\n  scheduler_address: ''\nindex_gateway:\n  mode: simple\nlimits_config:\n  allow_structured_metadata: false\n  ingestion_burst_size_mb: 0.1\n  ingestion_rate_mb: 0.02\n  max_cache_freshness_per_query: 10m\n  max_entries_limit_per_query: 1000\n  max_global_streams_per_user: 128\n  max_line_size: 4096\n  max_query_lookback: 168h\n  query_timeout: 300s\n  reject_old_samples: true\n  reject_old_samples_max_age: 168h\n  retention_period: 72h\n  retention_stream:\n  - period: 168h\n    priority: 1\n    selector: '{kind=\"identity-audit\"}'\n  split_queries_by_interval: 15m\n  volume_enabled: true\nmemberlist:\n  join_members:\n  - obs-storage-{{ .Values.operationId }}-loki-memberlist.obs-storage-{{ .Values.operationId }}.svc.cluster.local\npattern_ingester:\n  enabled: false\nquery_range:\n  align_queries_with_step: true\nruler:\n  storage:\n    type: local\n  wal:\n    dir: /var/loki/ruler-wal\nruntime_config:\n  file: /etc/loki/runtime-config/runtime-config.yaml\nschema_config:\n  configs:\n  - from: '2026-01-01'\n    index:\n      period: 24h\n      prefix: index_\n    object_store: filesystem\n    schema: v13\n    store: tsdb\nserver:\n  grpc_listen_port: 9095\n  http_listen_port: 3100\n  http_server_read_timeout: 600s\n  http_server_write_timeout: 600s\nstorage_config:\n  bloom_shipper:\n    working_directory: /var/loki/data/bloomshipper\n  boltdb_shipper:\n    index_gateway_client:\n      server_address: ''\n  hedging:\n    at: 250ms\n    max_per_second: 20\n    up_to: 3\n  tsdb_shipper:\n    index_gateway_client:\n      server_address: ''\n  use_thanos_objstore: false\ntracing:\n  enabled: false\n"
  }
}
{{- end -}}

{{- define "storage.config.tempo" -}}
{
  "apiVersion": "v1",
  "kind": "ConfigMap",
  "metadata": {
    "name": "obs-storage-{{ .Values.operationId }}-tempo-config",
    "namespace": "obs-storage-{{ .Values.operationId }}",
    "labels": {
      "helm.sh/chart": "tempo-3.1.0",
      "app.kubernetes.io/name": "tempo",
      "app.kubernetes.io/instance": "cloudlab-tempo",
      "app.kubernetes.io/version": "3.1.0",
      "app.kubernetes.io/managed-by": "Helm",
      "cloudlab.io/owner": "observability-lifecycle-proof",
      "cloudlab.io/storage-proof": "{{ .Values.operationId }}"
    }
  },
  "data": {
    "overrides.yaml": "overrides:\n  {}\n",
    "tempo.yaml": "stream_over_http_enabled: false\nmemberlist:\n  cluster_label: obs-storage-{{ .Values.operationId }}-tempo.obs-storage-{{ .Values.operationId }}\nmultitenancy_enabled: false\nusage_report:\n  reporting_enabled: false\nbackend_scheduler:\n  provider:\n    compaction:\n      compaction:\n        block_retention: 24h\ndistributor:\n  receivers:\n    jaeger:\n      protocols:\n        grpc:\n          endpoint: 0.0.0.0:14250\n        thrift_binary:\n          endpoint: 0.0.0.0:6832\n        thrift_compact:\n          endpoint: 0.0.0.0:6831\n        thrift_http:\n          endpoint: 0.0.0.0:14268\n    otlp:\n      protocols:\n        grpc:\n          endpoint: 0.0.0.0:4317\n        http:\n          endpoint: 0.0.0.0:4318\nserver:\n  http_listen_port: 3200\nstorage:\n  trace:\n    backend: local\n    local:\n      path: /var/tempo/traces\n    wal:\n      path: /var/tempo/wal\nquerier: {}\nquery_frontend: {}\noverrides:\n  defaults:\n    global:\n      max_bytes_per_trace: 65536\n    ingestion:\n      burst_size_bytes: 120000\n      rate_limit_bytes: 60000\n  per_tenant_override_config: /conf/overrides.yaml\n"
  }
}
{{- end -}}

{{- define "storage.config.grafana" -}}
{
  "apiVersion": "v1",
  "kind": "ConfigMap",
  "metadata": {
    "name": "obs-storage-{{ .Values.operationId }}-grafana-config",
    "namespace": "obs-storage-{{ .Values.operationId }}",
    "labels": {
      "helm.sh/chart": "grafana-13.5.1",
      "app.kubernetes.io/name": "grafana",
      "app.kubernetes.io/instance": "cloudlab-prometheus",
      "app.kubernetes.io/version": "13.2.4",
      "cloudlab.io/owner": "observability-lifecycle-proof",
      "cloudlab.io/storage-proof": "{{ .Values.operationId }}"
    }
  },
  "data": {
    "grafana.ini": "[alerting]\nenabled = false\n[analytics]\ncheck_for_plugin_updates = false\ncheck_for_updates = false\nreporting_enabled = false\n[auth]\ndisable_login_form = false\nlogin_maximum_inactive_lifetime_duration = 5m\nlogin_maximum_lifetime_duration = 5m\noauth_allow_insecure_email_lookup = false\nsignout_redirect_url = https://login.example.invalid/realms/platform/protocol/openid-connect/logout?post_logout_redirect_uri=https%3A%2F%2Fgrafana.internal.example.invalid%2Flogin\ntoken_rotation_interval_minutes = 1\n[auth.anonymous]\nenabled = false\n[auth.generic_oauth]\nallow_assign_grafana_admin = false\nallow_sign_up = true\napi_url = https://login.example.invalid/realms/platform/protocol/openid-connect/userinfo\nauth_url = https://login.example.invalid/realms/platform/protocol/openid-connect/auth\nauto_login = false\nclient_id = grafana\nclient_secret = $__file{/etc/secrets/grafana-oidc/client_secret}\nenabled = true\nlogin_attribute_path = sub\nname = Keycloak\nrole_attribute_path = contains(groups[*], '/platform-admin') && 'Admin' || contains(groups[*], '/developer') && 'Editor' || contains(groups[*], '/viewer') && 'Viewer' || ''\nrole_attribute_strict = true\nscopes = openid profile email\nskip_org_role_sync = false\ntoken_url = https://login.example.invalid/realms/platform/protocol/openid-connect/token\nuse_pkce = true\nuse_refresh_token = true\n[dashboards]\ndefault_home_dashboard_path = /var/lib/grafana/dashboards/cloudlab/nodes.json\n[log]\nmode = console\n[paths]\ndata = /var/lib/grafana/\nlogs = /var/log/grafana\nplugins = /var/lib/grafana/plugins\nprovisioning = /etc/grafana/provisioning\n[plugins]\nplugin_admin_enabled = false\npreinstall = \npreinstall_auto_update = false\npreinstall_disabled = true\npreinstall_sync = \npublic_key_retrieval_disabled = true\n[security]\ncookie_samesite = lax\ncookie_secure = true\ndisable_gravatar = true\nsecret_key = $__file{/etc/secrets/grafana-emergency/secret_key}\n[server]\ndomain = ''\nroot_url = https://grafana.internal.example.invalid\n[unified_alerting]\nenabled = false\n[unified_storage]\nindex_path = /var/lib/grafana-search/bleve\n[users]\nallow_sign_up = false\n",
    "datasources.yaml": "apiVersion: 1\ndatasources:\n- access: proxy\n  editable: false\n  isDefault: true\n  name: Prometheus\n  type: prometheus\n  uid: metrics\n  url: http://unused.fixture.invalid:9090\n- access: proxy\n  editable: false\n  jsonData:\n    derivedFields:\n    - datasourceUid: traces\n      matcherRegex: '\"trace_id\":\"([a-f0-9]{32})\"'\n      name: TraceID\n      url: $${__value.raw}\n  name: Loki\n  type: loki\n  uid: logs\n  url: http://obs-storage-{{ .Values.operationId }}-loki:3100\n- access: proxy\n  editable: false\n  jsonData:\n    nodeGraph:\n      enabled: true\n    tracesToLogsV2:\n      datasourceUid: logs\n      filterByTraceID: true\n  name: Tempo\n  type: tempo\n  uid: traces\n  url: http://obs-storage-{{ .Values.operationId }}-tempo:3200\nprune: true\n",
    "providers.yaml": "apiVersion: 1\nproviders:\n- allowUiUpdates: false\n  disableDeletion: false\n  folder: CloudLab\n  name: cloudlab\n  options:\n    path: /var/lib/grafana/dashboards/cloudlab\n  orgId: 1\n  type: file\n"
  }
}
{{- end -}}
