"""Verify declared storage policy, node readiness and replica placement."""

from kube import get, wait

def conditions_ready(conditions, names):
    values = {item['type']: item['status'] for item in conditions}
    return all(values.get(name) == 'True' for name in names)


def healthy_volume(name, expected_nodes):
    volume = get('volumes.longhorn.io', name)
    if volume.get('status', {}).get('robustness') != 'healthy':
        return False
    replicas = [r for r in get('replicas.longhorn.io')['items'] if r['spec'].get('volumeName') == name]
    running = [r for r in replicas if r.get('status', {}).get('currentState') == 'running'
               and not r['spec'].get('failedAt')]
    if len(running) != 2 or {r['spec']['nodeID'] for r in running} != set(expected_nodes):
        return False
    engines = [e for e in get('engines.longhorn.io')['items'] if e['spec'].get('volumeName') == name
               and e.get('status', {}).get('currentState') == 'running']
    return len(engines) == 1 and list(engines[0]['status'].get('replicaModeMap', {}).values()).count('RW') == 2


def verify_health(config):
    nodes = config['nodes']
    if len(nodes) != 2 or len(set(nodes)) != 2:
        raise ValueError('Verification requires two distinct nodes')
    policy = config['policy']
    for name, value in policy['settings'].items():
        actual = get('settings.longhorn.io', name)['value']
        if actual != value:
            raise RuntimeError('Longhorn setting differs from declared policy: ' + name)
    def ready_nodes():
        found = get('nodes.longhorn.io')['items']
        return len(found) == 2 and {n['metadata']['name'] for n in found} == set(nodes) and all(
            conditions_ready(n.get('status', {}).get('conditions', []),
                             ['Ready', 'Schedulable', 'RequiredPackages', 'NFSClientInstalled',
                              'MountPropagation'])
            and n.get('status', {}).get('diskStatus')
            and all(conditions_ready(d.get('conditions', []), ['Ready', 'Schedulable'])
                    for d in n['status']['diskStatus'].values()) for n in found)
    wait('Both storage nodes and disks ready', ready_nodes)
    pods = get('pods')['items']
    for pod in pods:
        for container in pod['spec'].get('containers', []) + pod['spec'].get('initContainers', []):
            if '@sha256:' not in container['image']:
                raise RuntimeError('Longhorn pod contains an unpinned image')
    frontend = get('service', 'longhorn-frontend')
    if frontend['spec']['type'] != 'ClusterIP':
        raise RuntimeError('Longhorn UI must remain private')
    print('Declared policy, image digests and private UI: passed', flush=True)

    if config['backup']:
        policy = config['backup_policy']
        job = get('recurringjobs.longhorn.io', policy['job_name'])['spec']
        if any(job[key] != policy[key] for key in ('cron', 'retain', 'concurrency')):
            raise RuntimeError('Backup schedule differs from declared policy')
        print('Monthly backup schedule and retention: passed', flush=True)
