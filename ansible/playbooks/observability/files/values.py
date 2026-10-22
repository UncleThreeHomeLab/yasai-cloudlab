"""Bounded upstream chart settings; no secrets or deployment addresses."""
import json
from pathlib import Path

from playbooks.observability.files.configuration import POLICY, grafana

BASE = Path(__file__).resolve().parents[4] / 'platform/observability'


def resources(cpu, memory, requested_cpu=20, requested_memory=64):
    return {'requests': {'cpu': str(requested_cpu) + 'm', 'memory': str(requested_memory) + 'Mi'},
            'limits': {'cpu': str(cpu) + 'm', 'memory': str(memory) + 'Mi'}}


def values(name):
    images = json.loads((BASE / 'images.lock.json').read_text())
    storage = POLICY['storage_class']
    def image(key):
        path, digest = images[key].split('@')
        repository, tag = path.rsplit(':', 1)
        registry, repository = repository.split('/', 1)
        return {'registry': registry, 'repository': repository, 'tag': tag, 'sha': digest.split(':')[1]}
    def claim(size):
        return {'volumeClaimTemplate': {'spec': {'storageClassName': storage, 'accessModes': ['ReadWriteOnce'],
                'resources': {'requests': {'storage': str(size) + 'Gi'}}}}}
    def digest_image(key):
        result = image(key)
        result['digest'] = 'sha256:' + result.pop('sha')
        return result
    if name == 'prometheus':
        ini = grafana('https://login.example.invalid/realms/platform', 'https://grafana.internal.example.invalid')['ini']
        return {
            'fullnameOverride': 'cloudlab', 'cleanPrometheusOperatorObjectNames': True,
            'crds': {'annotations': {'argocd.argoproj.io/sync-options': 'ServerSideApply=true,Prune=false,Delete=false'}},
            'kubeControllerManager': {'enabled': False}, 'kubeScheduler': {'enabled': False},
            'kubeEtcd': {'enabled': False}, 'kubeProxy': {'enabled': False},
            'coreDns': {'enabled': False, 'serviceMonitor': {'authorization': None}},
            'kubelet': {'serviceMonitor': {'authorization': None, 'labelValueLengthLimit': 512,
                # K3s shares its metric registry; the API-server job owns these series.
                'metricRelabelings': [{'sourceLabels': ['__name__'], 'regex': 'apiserver_.*', 'action': 'drop'}],
                'bearerTokenFile': '/var/run/secrets/kubernetes.io/serviceaccount/token',
                'tlsConfig': {'insecureSkipVerify': False}}},
            'kubeApiServer': {'serviceMonitor': {'authorization': None,
                'sampleLimit': 100000,
                'bearerTokenFile': '/var/run/secrets/kubernetes.io/serviceaccount/token'}},
            'prometheusOperator': {'fullnameOverride': 'cloudlab-prometheus-operator',
                'tls': {'enabled': False}, 'admissionWebhooks': {'enabled': False},
                'image': image('operator'), 'resources': resources(150, 256),
                'namespaces': {'releaseNamespace': True, 'additional': ['cloudlab-app-notes']},
                'prometheusInstanceNamespaces': [POLICY['namespace']], 'alertmanagerInstanceNamespaces': [POLICY['namespace']],
                'alertmanagerConfigNamespaces': [POLICY['namespace']],
                'prometheusConfigReloader': {'image': image('reloader'), 'resources': resources(25, 48, 5, 16)}},
            'prometheus': {'serviceAccount': {'name': 'cloudlab-prometheus', 'createTokenSecret': False},
                'serviceMonitor': {'labelValueLengthLimit': 512}, 'prometheusSpec': {
                'image': image('prometheus'), 'retention': POLICY['prometheus']['retention'],
                'retentionSize': POLICY['prometheus']['retention_size'], 'replicas': 1,
                'resources': resources(800, 2048, 150, 512), 'storageSpec': claim(POLICY['prometheus']['pvc_gib']),
                'serviceMonitorSelectorNilUsesHelmValues': False, 'podMonitorSelectorNilUsesHelmValues': False,
                'ruleSelectorNilUsesHelmValues': False, 'scrapeInterval': '30s', 'evaluationInterval': '30s',
                'sampleLimit': 50000, 'labelLimit': 40, 'labelNameLengthLimit': 100, 'labelValueLengthLimit': 200,
                'enableAdminAPI': False, 'enableRemoteWriteReceiver': False}},
            'alertmanager': {'alertmanagerSpec': {'image': image('alertmanager'), 'replicas': 1,
                'resources': resources(100, 128), 'storage': {'emptyDir': {'sizeLimit': '64Mi'}}},
                'config': {'global': {'resolve_timeout': '1m'},
                    'route': {'receiver': 'private', 'routes': [], 'group_by': ['alertname', 'service', 'severity'],
                              'group_wait': '10s', 'group_interval': '1m', 'repeat_interval': '4h'},
                    'receivers': [{'name': 'private'}]}},
            'grafana': {'fullnameOverride': 'cloudlab-grafana', 'image': image('grafana'),
                'deploymentStrategy': {'type': 'Recreate'},
                'serviceAccount': {'automountServiceAccountToken': False}, 'automountServiceAccountToken': False,
                'admin': {'existingSecret': 'grafana-emergency', 'userKey': 'username', 'passwordKey': 'password'},
                'resources': resources(250, 768, requested_memory=512), 'initChownData': {'enabled': False},
                'testFramework': {'enabled': False}, 'sidecar': {'dashboards': {'enabled': False}, 'datasources': {'enabled': False}},
                'defaultDashboardsEnabled': False, 'persistence': {'enabled': True, 'storageClassName': storage,
                                                              'size': str(POLICY['grafana']['pvc_gib']) + 'Gi'},
                'extraSecretMounts': [{'name': 'grafana-oidc', 'secretName': 'grafana-oidc',
                    'mountPath': '/etc/secrets/grafana-oidc', 'readOnly': True},
                    {'name': 'grafana-emergency', 'secretName': 'grafana-emergency',
                     'mountPath': '/etc/secrets/grafana-emergency', 'readOnly': True}],
                'grafana.ini': ini,
                'datasources': {'datasources.yaml': {'apiVersion': 1, 'prune': True, 'datasources': [
                    {'uid': 'metrics', 'name': 'Prometheus', 'type': 'prometheus', 'access': 'proxy',
                     'url': 'http://cloudlab-prometheus:9090', 'isDefault': True, 'editable': False},
                    {'uid': 'logs', 'name': 'Loki', 'type': 'loki', 'access': 'proxy', 'url': 'http://cloudlab-loki:3100',
                     'editable': False, 'jsonData': {'derivedFields': [{'name': 'TraceID', 'matcherRegex': '"trace_id":"([a-f0-9]{32})"',
                                                    'datasourceUid': 'traces', 'url': '$${__value.raw}'}]}},
                    {'uid': 'traces', 'name': 'Tempo', 'type': 'tempo', 'access': 'proxy', 'url': 'http://cloudlab-tempo:3200',
                     'editable': False, 'jsonData': {'tracesToLogsV2': {'datasourceUid': 'logs',
                                       'filterByTraceID': True}, 'nodeGraph': {'enabled': True}}}]}},
                'dashboardProviders': {'providers.yaml': {'apiVersion': 1, 'providers': [
                    {'name': 'cloudlab', 'orgId': 1, 'folder': 'CloudLab', 'type': 'file',
                     'disableDeletion': False, 'allowUiUpdates': False, 'options': {'path': '/var/lib/grafana/dashboards/cloudlab'}}]}},
                'dashboardsConfigMaps': {'cloudlab': 'cloudlab-dashboards'}},
            'kube-state-metrics': {'image': dict(image('ksm'), sha='sha256:' + image('ksm')['sha']),
                                  'resources': resources(75, 128)},
            'prometheus-node-exporter': {'image': dict(digest_image('node'), distroless=False), 'resources': resources(50, 64, 10, 32)},
        }
    if name == 'loki':
        return {'fullnameOverride': 'cloudlab-loki', 'deploymentMode': 'SingleBinary',
            'loki': {'image': {'registry': 'docker.io', 'repository': 'grafana/loki', 'digest': 'sha256:' + image('loki')['sha']},
                'auth_enabled': False, 'analytics': {'reporting_enabled': False},
                'commonConfig': {'replication_factor': 1}, 'storage': {'type': 'filesystem'},
                'schemaConfig': {'configs': [{'from': '2026-01-01', 'store': 'tsdb', 'object_store': 'filesystem',
                    'schema': 'v13', 'index': {'prefix': 'index_', 'period': '24h'}}]},
                'limits_config': {'retention_period': POLICY['loki']['retention'],
                    'retention_stream': [{'selector': '{kind="identity-audit"}', 'priority': 1,
                                          'period': str(POLICY['identity_audit']['retention_hours']) + 'h'}],
                    'ingestion_rate_mb': POLICY['loki']['ingestion_rate_mb'], 'ingestion_burst_size_mb': POLICY['loki']['ingestion_burst_mb'],
                    'max_global_streams_per_user': POLICY['loki']['max_streams'], 'max_line_size': 4096,
                    'max_query_lookback': '168h', 'max_entries_limit_per_query': 1000, 'reject_old_samples': True,
                    'reject_old_samples_max_age': '168h', 'allow_structured_metadata': False},
                'compactor': {'working_directory': '/var/loki/compactor', 'retention_enabled': True,
                    'delete_request_store': 'filesystem', 'retention_delete_delay': '15m', 'compaction_interval': '10m'}},
            'singleBinary': {'replicas': 1, 'resources': resources(400, 768, 100, 256),
                'persistence': {'enabled': True, 'storageClass': storage, 'size': str(POLICY['loki']['pvc_gib']) + 'Gi'}},
            'read': {'replicas': 0}, 'write': {'replicas': 0}, 'backend': {'replicas': 0},
            'gateway': {'enabled': False}, 'lokiCanary': {'enabled': False}, 'test': {'enabled': False},
            'chunksCache': {'enabled': False}, 'resultsCache': {'enabled': False},
            'sidecar': {'rules': {'enabled': False}}, 'serviceAccount': {'automountServiceAccountToken': False}}
    if name == 'tempo':
        return {'fullnameOverride': 'cloudlab-tempo', 'tempo': {
            'repository': 'grafana/tempo', 'tag': image('tempo')['tag'] + '@sha256:' + image('tempo')['sha'],
            'reportingEnabled': False, 'resources': resources(400, 768, 100, 256),
            'retention': POLICY['tempo']['retention'], 'receivers': {'otlp': {'protocols': {'http': {'endpoint': '0.0.0.0:4318'}}}},
            'overrides': {'defaults': {'ingestion': {'rate_limit_bytes': POLICY['tempo']['ingestion_rate_bytes'],
                   'burst_size_bytes': 120000}, 'global': {'max_bytes_per_trace': POLICY['tempo']['max_trace_bytes']}}}},
            'tempoQuery': {'enabled': False}, 'serviceAccount': {'automountServiceAccountToken': False},
            'persistence': {'enabled': True, 'storageClassName': storage, 'size': str(POLICY['tempo']['pvc_gib']) + 'Gi'}}
    if name == 'alloy':
        return {'fullnameOverride': 'cloudlab-alloy', 'image': {'registry': 'docker.io', 'repository': 'grafana/alloy',
                                                             'digest': 'sha256:' + image('alloy')['sha']},
            'crds': {'create': False},
            'controller': {'type': 'deployment', 'replicas': 1, 'updateStrategy': {'type': 'RollingUpdate',
                           'rollingUpdate': {'maxSurge': 0, 'maxUnavailable': 1}}}, 'configReloader': {'enabled': False},
            'serviceAccount': {'name': 'cloudlab-alloy'}, 'alloy': {'enableReporting': False,
                'resources': resources(250, 384, 50, 128), 'configMap': {'create': False, 'name': 'cloudlab-alloy', 'key': 'config.alloy'},
                'extraPorts': [{'name': 'otlp-http', 'port': 4318, 'targetPort': 4318, 'protocol': 'TCP', 'appProtocol': 'http'}]},
            'rbac': {'create': True, 'namespaces': ['cloudlab-app-notes', 'cloudlab-identity'], 'clusterRules': [],
                     'rules': [{'apiGroups': [''], 'resources': ['pods', 'pods/log'], 'verbs': ['get', 'list', 'watch']}]}}
    if name == 'kiali':
        return {'login_token': {'signing_key': 'secret:kiali-signing-key:key'},
            'kiali_feature_flags': {'disabled_features': ['logs-tab']},
            'auth': {'strategy': 'openid', 'openid': {'client_id': 'kiali',
            'issuer_uri': 'https://login.example.invalid/realms/platform', 'username_claim': 'sub', 'disable_rbac': True}},
            'deployment': {'instance_name': 'cloudlab-kiali', 'image_version': image('kiali')['sha'], 'image_digest': 'sha256',
                'cluster_wide_access': False, 'view_only_mode': True, 'resources': resources(200, 384),
                'strategy': {'type': 'Recreate'},
                'discovery_selectors': {'default': [{'matchLabels': {'kubernetes.io/metadata.name': namespace}}
                    for namespace in POLICY['kiali']['namespaces']]},
                'network_policy': {'enabled': False}}, 'clustering': {'autodetect_secrets': {'enabled': False}},
            'external_services': {'prometheus': {'url': 'http://cloudlab-prometheus:9090'},
                'grafana': {'enabled': True, 'internal_url': 'http://cloudlab-grafana',
                    'external_url': 'https://grafana.internal.example.invalid'},
                'tracing': {'enabled': True, 'provider': 'tempo', 'internal_url': 'http://cloudlab-tempo:3200',
                            'use_grpc': False}}, 'istio_namespace': 'istio-system'}
    raise ValueError('Unknown telemetry component')
