"""Read-only fixed probe bindings and effective stream logging prerequisites."""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from playbooks.k3s.files.native_custody import Session as native_session
from playbooks.previews.files import contract
from playbooks.previews.files.lifecycle import owned
from playbooks.previews.files.resources import resources, workload
from playbooks.istio.files.kube import contains, get

ROOT = Path('/var/lib/cloudlab/preview-fixtures')


def refused():
    raise ValueError('Private probe prerequisite unavailable')


def command(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=15,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode or len(result.stdout) > 262144: refused()
    return result.stdout


def file(path):
    target = Path(path)
    if target.is_symlink() or not target.is_file() or target.stat().st_size > 262144: refused()
    return target.read_text()


def bash_startup_safe(raw):
    effective = '\n'.join(line.strip() for line in raw.splitlines() if line.strip() and not line.lstrip().startswith('#'))
    return not effective or effective.startswith('[ -z "$PS1" ] && return\n') or bool(
        re.match(r'^case \$- in\n\*i\*\)\s*;;\n\*\)\s*return\s*;;\nesac(?:\n|$)', effective))


def assurance(native):
    """Support only the inspected native root SSH/local K3s chain; unknown means stop."""
    if os.geteuid() != 0 or os.isatty(0) or not os.environ.get('SSH_CONNECTION'): refused()
    if any(value for key, value in os.environ.items() if key.upper().endswith('_PROXY') or key in (
            'KUBECONFIG', 'K3S_URL', 'K3S_TOKEN', 'K3S_CONFIG_FILE', 'BASH_ENV', 'ENV', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'SSH_TTY')):
        refused()
    connection = os.environ['SSH_CONNECTION'].split()
    if len(connection) != 4: refused()
    for address in (connection[0], connection[2]): ipaddress.ip_address(address)
    server = command(['/usr/sbin/sshd', '-T', '-C', 'user=root,addr=' + connection[0] + ',laddr=' + connection[2] + ',lport=' + connection[3]])
    options = dict(line.split(' ', 1) for line in server.splitlines() if ' ' in line)
    if (options.get('forcecommand') != 'none' or options.get('permituserenvironment') != 'no' or
            options.get('loglevel') not in ('QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE') or
            options.get('pamservicename', 'sshd') != 'sshd' or
            any(value not in ('LANG', 'LC_*', 'COLORTERM', 'NO_COLOR') for value in options.get('acceptenv', '').split())):
        refused()
    # Modified PAM, sshd or shell package files invalidate this narrow assurance.
    if command(['dpkg', '--verify', 'openssh-server', 'libpam-modules', 'libpam-runtime', 'bash']).strip(): refused()
    passwd = next((line.split(':') for line in file('/etc/passwd').splitlines() if line.startswith('root:')), None)
    if not passwd or passwd[-1] != '/bin/bash' or passwd[-2] != '/root': refused()
    for candidate in ('/root/.ssh/rc', '/etc/ssh/sshrc'):
        target = Path(candidate)
        if target.exists():
            raw = file(candidate)
            if any(line.strip() and not line.lstrip().startswith('#') for line in raw.splitlines()): refused()
    # Stock Bash returns before executing interactive startup commands for SSH -c.
    startup = Path('/root/.bashrc')
    if startup.exists():
        if not bash_startup_safe(file(str(startup))): refused()
    # No sudo, recording shell or ForceCommand wrapper may sit on this invocation.
    parent = os.getppid()
    ancestry = []
    for _ in range(3):
        executable = str(Path('/proc/' + str(parent) + '/exe').resolve())
        args = Path('/proc/' + str(parent) + '/cmdline').read_bytes().split(b'\0')
        ancestry.append(executable)
        if executable in ('/usr/sbin/sshd', '/usr/lib/openssh/sshd-session'):
            package = command(['dpkg-query', '--search', executable]).strip()
            if package not in ('openssh-server: ' + executable, 'openssh-server:amd64: ' + executable): refused()
            if executable == '/usr/lib/openssh/sshd-session' and options.get('pamservicename') != 'sshd': refused()
            break
        if executable not in ('/usr/bin/bash', '/bin/bash') or args[1:3] != [b'-c', b'python3 /opt/cloudlab/playbooks/previews/tests/probe_inspection.py']:
            refused()
        parent = int(next(line.split()[1] for line in file('/proc/' + str(parent) + '/status').splitlines() if line.startswith('PPid:')))
    else: refused()
    pam = file('/etc/pam.d/sshd') + file('/etc/pam.d/common-session') + file('/etc/pam.d/common-session-noninteractive')
    if re.search(r'pam_(?:exec|tty_audit|script|tlog)|record|session\s+\S+\s+[^\s]+\s+.*(?:log_input|iolog)', pam, re.I): refused()
    native_snapshot = native.observe()
    # Refuse known dynamic input recording even when SSH itself is ordinary.
    for service in ('tlog-rec-session.service', 'sshd-session-recording.service'):
        result = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True, timeout=10)
        if result.returncode not in (3, 4) or result.stdout.strip() not in ('inactive', 'unknown') or result.stderr.strip(): refused()
    return contract.digest(contract.canonical({'sshd': server, 'ancestry': ancestry,
        'native': native_snapshot, 'pam': pam}))


def host_owner(revision):
    from playbooks.previews.tests.resource_runtime import platform, HostKubernetes
    platform({'revision': revision}, HostKubernetes())


def receipt(nonce):
    if not isinstance(nonce, str) or not re.fullmatch('[a-f0-9]{32}', nonce): refused()
    directory = ROOT / nonce; target = directory / 'state.json'
    if ROOT.is_symlink() or directory.is_symlink() or directory.stat().st_mode & 0o077: refused()
    descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 262144: refused()
        value = json.load(stream)
    if value.get('nonce') != nonce: refused()
    return value


def bound_probe(state):
    namespace = 'cloudlab-fixture-probe-' + state['nonce']
    result = {}
    for version, kind, name in (('v1', 'Namespace', namespace), ('v1', 'Pod', 'probe'), ('v1', 'Service', 'control'),
                               ('v1', 'ConfigMap', 'probe-code'), ('v1', 'ResourceQuota', 'budget'),
                               ('networking.k8s.io/v1', 'NetworkPolicy', 'probe')):
        key = (version, kind, '' if kind == 'Namespace' else namespace, name)
        record = state.get('resources', {}).get('/'.join(key), {})
        actual = get(kind.lower() + ('.' + version.split('/')[0] if '/' in version else ''), name, key[2] or None)
        if (not record.get('uid') or record.get('deleted') or not actual or actual['metadata']['uid'] != record['uid'] or
                not contains(actual, record['desired']) or actual['metadata'].get('deletionTimestamp')): refused()
        result[kind] = actual
    labels = result['Namespace']['metadata'].get('labels', {})
    if labels.get('istio.io/dataplane-mode') or labels.get('istio.io/use-waypoint'):
        refused()
    service = result['Service']['spec']
    if service.get('type', 'ClusterIP') != 'ClusterIP' or service.get('externalIPs') or service.get('externalName'):
        refused()
    pod = result['Pod']
    desired = state['resources']['v1/Pod/' + namespace + '/probe']['desired']['spec']
    actual_spec = pod.get('spec', {})
    if (actual_spec.get('hostNetwork', False) or actual_spec.get('hostPID', False) or actual_spec.get('hostIPC', False) or
            actual_spec.get('shareProcessNamespace', False) or actual_spec.get('initContainers') or actual_spec.get('ephemeralContainers') or
            len(actual_spec.get('containers', [])) != 1 or
            any(actual_spec['containers'][0].get(field) != desired['containers'][0].get(field) for field in ('command', 'args', 'env', 'envFrom', 'volumeMounts'))):
        refused()
    if pod.get('status', {}).get('phase') != 'Running' or not any(
            c.get('type') == 'Ready' and c.get('status') == 'True' for c in pod.get('status', {}).get('conditions', [])): refused()
    return result


def targets(rows, revision):
    catalog = get('configmap', contract.APPROVALS, 'argocd')
    if catalog['metadata'].get('labels', {}).get('cloudlab.io/owner') != contract.OWNER: refused()
    settings = contract.runtime_catalog(json.loads(catalog['data']['catalog.json']))
    state = get('configmap', contract.STATE, 'argocd')
    if state['metadata'].get('labels', {}).get('cloudlab.io/owner') != contract.OWNER: refused()
    runtime = json.loads(state['data']['state.json'])['entries']
    application = get('application.argoproj.io', 'cloudlab-previews', 'argocd')
    source = application['spec']['sources'][0]
    if (application['metadata'].get('labels', {}).get('cloudlab.io/owner') != contract.OWNER or
            source['targetRevision'] != revision or application['status']['sync'].get('revisions', [None])[0] != revision or
            application['status']['health']['status'] != 'Healthy'): refused()
    gateway = get('service', 'cloudlab-istio', 'cloudlab-gateway-private')
    gateway_owner = get('gateway.gateway.networking.k8s.io', 'cloudlab', 'cloudlab-gateway-private')
    if (not gateway_owner or gateway_owner.get('spec', {}).get('gatewayClassName') != 'istio' or
            not any(ref.get('kind') == 'Gateway' and ref.get('uid') == gateway_owner['metadata']['uid']
                    for ref in gateway.get('metadata', {}).get('ownerReferences', [])) or
            gateway['spec'].get('type', 'ClusterIP') != 'ClusterIP' or gateway['spec'].get('externalIPs')): refused()
    gateway_ip = gateway['spec']['clusterIP']; ipaddress.ip_address(gateway_ip)
    snapshot, declarations = [], []
    for row in rows:
        contract.approval(row)
        if row['definition']['profile'] != 'synthetic' or row['platformRevision'] != revision or row not in settings['approvals']: refused()
        entry = runtime[row['instance']]
        if entry.get('phase') != 'active' or entry.get('approval') != row: refused()
        n = contract.names(row); ns = n['namespace']
        uid_map = {'/'.join(item['key']): item['uid'] for item in entry['resources']}
        policies = []
        for desired in resources(row, settings, source['repoURL'], state['metadata']['uid']):
            if desired['kind'] not in ('NetworkPolicy', 'AuthorizationPolicy', 'RequestAuthentication', 'PeerAuthentication', 'Namespace'): continue
            version, kind = desired['apiVersion'], desired['kind']
            actual = get(kind.lower() + ('.' + version.split('/')[0] if '/' in version else ''), desired['metadata']['name'],
                         desired['metadata'].get('namespace'))
            key = '/'.join((version, kind, desired['metadata'].get('namespace', ''), desired['metadata']['name']))
            if not uid_map.get(key): refused()
            owned(actual, row, state['metadata']['uid'], uid_map.get(key))
            if not contains(actual, desired): refused()
            policies.append({'uid': actual['metadata']['uid'], 'spec': actual.get('spec'), 'labels': actual['metadata'].get('labels')})
        service, deployment = get('service', 'preview', ns), get('deployment.apps', 'preview', ns)
        for kind, version, actual in (('Service', 'v1', service), ('Deployment', 'apps/v1', deployment)):
            key = '/'.join((version, kind, ns, 'preview'))
            if not uid_map.get(key): refused()
            owned(actual, row, state['metadata']['uid'], uid_map[key])
        selector = service['spec'].get('selector')
        ports = service['spec'].get('ports', [])
        if (selector != {'app.kubernetes.io/name': 'preview'} or len(ports) != 1 or
                ports[0].get('port') != 8080 or ports[0].get('targetPort') != 'http' or ports[0].get('protocol', 'TCP') != 'TCP' or
                service['spec'].get('type', 'ClusterIP') != 'ClusterIP' or service['spec'].get('externalIPs')): refused()
        containers = deployment['spec']['template']['spec']['containers']
        if len(containers) != 1 or containers[0]['image'] != contract.IMAGE or deployment['status'].get('readyReplicas') != 1: refused()
        desired_workload = workload(row, settings, state['metadata']['uid'])
        if (containers[0].get('command') != desired_workload['command'] or containers[0].get('args') or
                containers[0].get('envFrom') or deployment['spec']['template']['spec'].get('automountServiceAccountToken') is not False):
            refused()
        environment = {value['name']: value.get('value') for value in containers[0].get('env', [])}
        if environment.get('CLOUDLAB_SOURCE_SHA') != row['sourceSha'] or environment.get('PREVIEW_MESSAGE') != row['definition']['message']: refused()
        replicas = (get('replicasets.apps', namespace=ns) or {}).get('items', [])
        replica_uids = {obj['metadata']['uid'] for obj in replicas if any(
            owner.get('uid') == deployment['metadata']['uid'] and owner.get('kind') == 'Deployment'
            for owner in obj['metadata'].get('ownerReferences', []))}
        pods = [pod for pod in (get('pods', namespace=ns) or {}).get('items', []) if contains(pod['metadata'].get('labels', {}), selector)]
        if len(pods) != 1: refused()
        pod = pods[0]
        if (not any(owner.get('uid') in replica_uids and owner.get('kind') == 'ReplicaSet' for owner in pod['metadata'].get('ownerReferences', [])) or
                not contains(pod.get('spec', {}), deployment['spec']['template']['spec']) or
                not any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in pod.get('status', {}).get('conditions', []))): refused()
        pod_ip = pod['status']['podIP']; ipaddress.ip_address(pod_ip)
        slices = (get('endpointslices.discovery.k8s.io', namespace=ns) or {}).get('items', [])
        slices = [item for item in slices if item['metadata'].get('labels', {}).get('kubernetes.io/service-name') == 'preview']
        if len(slices) != 1 or not slices[0]['metadata'].get('uid') or not any(
                owner.get('kind') == 'Service' and owner.get('uid') == service['metadata']['uid']
                for owner in slices[0]['metadata'].get('ownerReferences', [])):
            refused()
        endpoints = [endpoint for item in slices for endpoint in item['endpoints']]
        if (len(endpoints) != 1 or endpoints[0].get('addresses') != [pod_ip] or endpoints[0].get('conditions', {}).get('ready') is not True or
                endpoints[0].get('targetRef', {}).get('uid') != pod['metadata']['uid'] or
                endpoints[0].get('targetRef', {}).get('kind') != 'Pod' or
                endpoints[0].get('targetRef', {}).get('namespace') != ns): refused()
        service_ip = service['spec']['clusterIP']; ipaddress.ip_address(service_ip)
        expected = {'message': row['definition']['message'], 'source': row['sourceSha']}
        base = {'host': contract.hostname(row, settings), 'path': n['path'], 'expected': expected}
        declarations.append({name: dict(base, address=address, tls=name == 'gateway') for name, address in (
            ('gateway', gateway_ip), ('service', service_ip), ('pod', pod_ip))})
        snapshot.append({'namespaceUID': uid_map['v1/Namespace//' + ns], 'serviceUID': service['metadata']['uid'],
            'podUID': pod['metadata']['uid'], 'podIP': pod_ip, 'serviceIP': service_ip,
            'policiesHash': contract.digest(contract.canonical(policies)),
            'endpointHash': contract.digest(contract.canonical([{'uid': item['metadata']['uid'], 'endpoints': item['endpoints'],
                'ports': item.get('ports')} for item in slices]))})
    return declarations, {'gatewayUID': gateway['metadata']['uid'], 'gatewayOwnerUID': gateway_owner['metadata']['uid'], 'targets': snapshot}
