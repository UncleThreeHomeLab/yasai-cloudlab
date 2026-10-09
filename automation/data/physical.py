"""Boot restored Longhorn PVCs without adding another snapshot controller."""
import json

from automation.data import control
from automation.mesh.kube import condition, get, kube, wait

NAMESPACE = 'cloudlab-data-restore'
LABEL = {'cloudlab.io/fixture': 'application-data-restore'}
CLAIMS = {'postgres': 'data-restore-1',
          'master': 'data-cloudlab-data-restore-data-restore-seaweedfs-master-0',
          'filer': 'data-filer-data-restore-seaweedfs-filer-0',
          'volume': 'data1-data-restore-seaweedfs-volume-0'}


def storage_class(component):
    if component not in CLAIMS:
        raise ValueError('Unexpected restore component')
    return NAMESPACE + '-' + component


def provision(manifest, offsite):
    base = get('storageclass', 'cloudlab-data')['parameters']
    for component, row in manifest['volumes'].items():
        name = storage_class(component)
        if get('storageclass', name):
            raise RuntimeError('Previous restore StorageClass remains; clean its owned fixture first')
        parameters = dict(base)
        parameters['fromBackup' if offsite else 'dataSource'] = row['url'] if offsite else 'snap://' + row['volume'] + '/' + row['snapshot']
        kube('create', '-f', '-', document={'apiVersion': 'storage.k8s.io/v1', 'kind': 'StorageClass',
             'metadata': {'name': name, 'labels': LABEL}, 'provisioner': 'driver.longhorn.io',
             'allowVolumeExpansion': True, 'reclaimPolicy': 'Delete', 'volumeBindingMode': 'Immediate',
             'parameters': parameters})
        kube('create', '-f', '-', document={'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim',
             'metadata': {'name': CLAIMS[component], 'namespace': NAMESPACE, 'labels': LABEL},
             'spec': {'accessModes': ['ReadWriteOnce'], 'storageClassName': name,
                      'resources': {'requests': {'storage': row['size']}}}})


def postgres(manifest):
    # This disposable recovery service runs the exact PostgreSQL image against
    # the physical backup. It does not ask initdb to overwrite restored PGDATA.
    ca = get('secret', 'cloudlab-postgres-ca', control.NAMESPACE)['data']
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Secret',
         'metadata': {'name': 'data-restore-ca', 'namespace': NAMESPACE, 'labels': LABEL},
         'type': 'Opaque', 'data': {'ca.crt': ca['ca.crt']}})
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Secret',
         'metadata': {'name': 'restore-signing-ca', 'namespace': NAMESPACE, 'labels': LABEL},
         'type': 'kubernetes.io/tls', 'data': {'tls.crt': ca['ca.crt'], 'tls.key': ca['ca.key']}})
    kube('apply', '-f', '-', document={'apiVersion': 'cert-manager.io/v1', 'kind': 'Issuer',
         'metadata': {'name': 'restore-sql', 'namespace': NAMESPACE, 'labels': LABEL},
         'spec': {'ca': {'secretName': 'restore-signing-ca'}}})
    kube('apply', '-f', '-', document={'apiVersion': 'cert-manager.io/v1', 'kind': 'Certificate',
         'metadata': {'name': 'restore-sql', 'namespace': NAMESPACE, 'labels': LABEL},
         'spec': {'secretName': 'restore-sql', 'dnsNames': ['data-restore-rw.' + NAMESPACE + '.svc'],
                  'issuerRef': {'name': 'restore-sql', 'kind': 'Issuer'}}})
    wait(lambda: condition(get('certificate.cert-manager.io', 'restore-sql', NAMESPACE), 'Ready'), 'restore SQL TLS')
    # Current production HBA and current vault passwords override stale access.
    source = get('cluster.postgresql.cnpg.io', 'cloudlab-postgres', control.NAMESPACE)['spec']
    config = "listen_addresses='*'\nport=5432\nssl=on\nssl_cert_file='/tls/tls.crt'\nssl_key_file='/tls/tls.key'\nssl_min_protocol_version='TLSv1.2'\npassword_encryption='scram-sha-256'\nhba_file='/restore/pg_hba.conf'\nunix_socket_directories='/tmp'\n"
    hba = 'local all postgres peer\n' + '\n'.join(source['postgresql']['pg_hba']) + '\n'
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'ConfigMap',
         'metadata': {'name': 'restore-postgres', 'namespace': NAMESPACE, 'labels': LABEL},
         'data': {'postgresql.conf': config, 'pg_hba.conf': hba}})
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Service',
         'metadata': {'name': 'data-restore-rw', 'namespace': NAMESPACE, 'labels': LABEL},
         'spec': {'selector': {'cloudlab.io/restore': 'postgres'}, 'ports': [{'port': 5432, 'targetPort': 5432}]}})
    kube('apply', '-f', '-', document={'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
         'metadata': {'name': 'restore-postgres', 'namespace': NAMESPACE, 'labels': LABEL},
         'spec': {'podSelector': {'matchLabels': {'cloudlab.io/restore': 'postgres'}}, 'policyTypes': ['Ingress'],
                  'ingress': [{'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'cloudlab-data-proof'}}}],
                               'ports': [{'protocol': 'TCP', 'port': 5432}]}]}})
    pin = json.loads((control.ROOT / 'platform/data/cnpg/artifact.lock.json').read_text())['postgres_image']
    security = {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}
    kube('apply', '-f', '-', document={'apiVersion': 'apps/v1', 'kind': 'Deployment',
         'metadata': {'name': 'restore-postgres', 'namespace': NAMESPACE, 'labels': LABEL},
         'spec': {'replicas': 1, 'strategy': {'type': 'Recreate'},
                  'selector': {'matchLabels': {'cloudlab.io/restore': 'postgres'}},
                  'template': {'metadata': {'labels': {'cloudlab.io/restore': 'postgres'}},
                    'spec': {'automountServiceAccountToken': False,
                       'securityContext': {'runAsNonRoot': True, 'runAsUser': 26, 'runAsGroup': 26, 'fsGroup': 26,
                                           'seccompProfile': {'type': 'RuntimeDefault'}},
                       # Kubelet fsGroup handling adds group write to restored
                       # directories. PostgreSQL requires its own data dir 0700.
                       'initContainers': [{'name': 'restore-permissions', 'image': pin,
                         'securityContext': security,
                         'command': ['chmod', '0700', '/var/lib/postgresql/data/pgdata'],
                         'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'},
                                       'limits': {'cpu': '100m', 'memory': '64Mi'}},
                         'volumeMounts': [{'name': 'data', 'mountPath': '/var/lib/postgresql/data'}]}],
                       'containers': [{'name': 'postgres', 'image': pin, 'securityContext': security,
                         'command': ['postgres', '-D', '/var/lib/postgresql/data/pgdata', '-c', 'config_file=/restore/postgresql.conf'],
                         'env': [{'name': 'PGHOST', 'value': '/tmp'}],
                         'resources': {'requests': {'cpu': '250m', 'memory': '512Mi'}, 'limits': {'cpu': '2', 'memory': '2Gi'}},
                         'readinessProbe': {'exec': {'command': ['pg_isready', '-h', '/tmp']}, 'periodSeconds': 3},
                         'volumeMounts': [{'name': 'data', 'mountPath': '/var/lib/postgresql/data'},
                                          {'name': 'config', 'mountPath': '/restore', 'readOnly': True},
                                          {'name': 'tls', 'mountPath': '/tls', 'readOnly': True}]}],
                       'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': CLAIMS['postgres']}},
                                   {'name': 'config', 'configMap': {'name': 'restore-postgres'}},
                                   {'name': 'tls', 'secret': {'secretName': 'restore-sql', 'defaultMode': 0o440}}]}}}})
    kube('rollout', 'status', 'deployment/restore-postgres', '-n', NAMESPACE, '--timeout=900s', timeout=930)


def cleanup_classes():
    for component in CLAIMS:
        name = storage_class(component)
        obj = get('storageclass', name)
        if obj:
            if obj['metadata'].get('labels', {}).get('cloudlab.io/fixture') != LABEL['cloudlab.io/fixture']:
                raise RuntimeError('Refusing to remove a foreign restore StorageClass')
            kube('delete', 'storageclass', name)
