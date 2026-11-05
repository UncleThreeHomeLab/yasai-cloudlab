"""Validate trusted native Docker inspect, then publish one fresh node receipt.

No Docker socket or host inspection API is exposed here. Full-ID authority comes
from the documented inspect/start CLI sequence; hostname only prevents replay.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time

import yaml

COMPOSE = Path(__file__).with_name('compose.lifecycle-stack.yaml')
VERSION = 'cloudlab-lifecycle-node-preflight/v1'
PURPOSE = 'observability-native-stack-proof'
MAX_INPUT = 1024 * 1024
MAX_AGE = 300
TTL = 120
HEX = re.compile(r'[a-f0-9]{64}')
PROJECT = re.compile(r'obs-lifecycle-stack-[a-z0-9][a-z0-9_-]{0,42}')
ANONYMOUS = {'/var/lib/kubelet', '/var/lib/cni', '/var/log'}
TMPFS = {'/run', '/var/lib/rancher/k3s', '/var/lib/lifecycle-storage'}
BASE_ENV = {
    'PATH=/var/lib/rancher/k3s/data/cni:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/bin/aux',
    'CRI_CONFIG_FILE=/var/lib/rancher/k3s/agent/etc/crictl.yaml',
}


class Refusal(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def canonical_startup():
    source = yaml.safe_load(COMPOSE.read_text())['services']['cluster']
    return source, [item.replace('$$', '$') for item in source['command']]


def strict_json(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_INPUT, 'Inspect input size invalid')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate inspect JSON key')
            result[key] = value
        return result
    try:
        result = json.loads(raw, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(Refusal('Nonfinite inspect JSON')))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Refusal('Inspect JSON invalid') from error
    require(type(result) is list and len(result) == 5 and all(type(v) is dict for v in result),
            'Inspect must contain one container and its four complete volumes')
    return result


def timestamp(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|\+00:00)', value),
            'Inspect timestamp invalid')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except ValueError as error:
        raise Refusal('Inspect timestamp invalid') from error


def validate(raw, container_id, project, now=None):
    """Pure validation: no filesystem changes, requests or external commands."""
    now = time.time() if now is None else now
    require(type(container_id) is str and HEX.fullmatch(container_id), 'Full container ID required')
    require(type(project) is str and PROJECT.fullmatch(project), 'Fixture project invalid')
    objects = strict_json(raw)
    containers = [v for v in objects if 'Id' in v]
    require(len(containers) == 1, 'Exactly one container required')
    node = containers[0]
    require(node.get('Id') == container_id and node.get('Name') == '/' + project + '-cluster-1', 'Container identity mismatch')
    created = timestamp(node.get('Created'))
    require(0 <= now - created <= MAX_AGE, 'Container is not fresh')
    state = node.get('State', {})
    require(type(state) is dict and state.get('Status') == 'created'
            and type(node.get('RestartCount')) is int and node['RestartCount'] == 0, 'Container already used')
    for key in ('Running', 'Paused', 'Restarting', 'OOMKilled', 'Dead'):
        require(state.get(key) is False, 'Container state invalid')
    for key in ('Pid', 'ExitCode'):
        require(type(state.get(key)) is int and state[key] == 0, 'Container state invalid')
    require(state.get('Error') == '' and state.get('StartedAt') == '0001-01-01T00:00:00Z'
            and state.get('FinishedAt') == '0001-01-01T00:00:00Z', 'Container was started')
    source, command = canonical_startup()
    config, host = node.get('Config', {}), node.get('HostConfig', {})
    require(type(config) is dict and type(host) is dict, 'Container configuration invalid')
    require(config.get('Image') == source['image'] and re.fullmatch(r'sha256:[a-f0-9]{64}', node.get('Image', '')),
            'Pinned container image changed')
    require(config.get('Entrypoint') == source['entrypoint'] and config.get('Cmd') == command
            and node.get('Path') == '/bin/sh' and node.get('Args') == ['-c', command[0]], 'Versioned startup changed')
    hostname = container_id[:12]
    require(config.get('Hostname') == hostname and config.get('Domainname') == '', 'Default hostname required')
    require(config.get('User', '') == '' and config.get('WorkingDir') == '/' and config.get('Healthcheck') is None,
            'Unexpected container execution configuration')
    for key in ('Tty', 'OpenStdin', 'StdinOnce'):
        require(config.get(key) is False, 'Unexpected interactive container')
    env = config.get('Env')
    require(type(env) is list and len(env) == 3 and set(env) == BASE_ENV | {'FIXTURE_PROJECT=' + project},
            'Unexpected node environment')
    labels = config.get('Labels', {})
    require(type(labels) is dict and labels.get('com.docker.compose.project') == project and labels.get('com.docker.compose.service') == 'cluster'
            and labels.get('cloudlab.io/purpose') == PURPOSE and labels.get('com.docker.compose.container-number') == '1'
            and labels.get('com.docker.compose.oneoff') == 'False', 'Container ownership mismatch')
    require(host.get('Privileged') is True and host.get('ReadonlyRootfs') is False, 'Node privilege configuration changed')
    require(type(host.get('Memory')) is int and host['Memory'] == 16 * 1024**3
            and type(host.get('NanoCpus')) is int and host['NanoCpus'] == 6 * 10**9, 'Node resource limits changed')
    for key in ('CpuShares', 'CpuPeriod', 'CpuQuota', 'CpuRealtimePeriod', 'CpuRealtimeRuntime',
                'MemoryReservation', 'BlkioWeight', 'OomScoreAdj'):
        require(type(host.get(key)) is int and host[key] == 0, 'Unexpected node resource override')
    require(host.get('CpusetCpus') == '' and host.get('CpusetMems') == ''
            and type(host.get('MemorySwap')) is int and host['MemorySwap'] in (0, 32 * 1024**3)
            and (host.get('PidsLimit') is None or type(host['PidsLimit']) is int and host['PidsLimit'] == 0)
            and (host.get('OomKillDisable') is None or host['OomKillDisable'] is False), 'Unexpected node resource override')
    require(type(host.get('ShmSize')) is int and host['ShmSize'] == 64 * 1024**2, 'Unexpected shared-memory limit')
    for key in ('PidMode', 'UTSMode', 'UsernsMode'):
        require(host.get(key, '') == '', 'Host namespace sharing forbidden')
    require(host.get('IpcMode') == 'private' and host.get('CgroupnsMode') == 'private', 'Unexpected namespace mode')
    for key in ('CapAdd', 'CapDrop', 'Devices', 'DeviceRequests', 'DeviceCgroupRules',
                'Links', 'ExtraHosts', 'Dns', 'DnsOptions', 'DnsSearch', 'VolumesFrom'):
        require(host.get(key) in (None, []), 'Unexpected host configuration')
    require(host.get('SecurityOpt') in (None, [], ['label=disable']), 'Unexpected security option override')
    require(host.get('Runtime') == 'runc' and host.get('ContainerIDFile', '') == ''
            and host.get('VolumeDriver', '') == '', 'Unexpected runtime or external storage configuration')
    require(host.get('Sysctls') in (None, {}) and host.get('Init') in (None, False)
            and host.get('PublishAllPorts') is False and host.get('PortBindings') in (None, {}), 'Host exposure forbidden')
    require(host.get('Tmpfs') == {path: '' for path in TMPFS}, 'Canonical tmpfs changed')
    networks = node.get('NetworkSettings', {})
    require(type(networks) is dict and type(networks.get('Networks')) is dict, 'Container networks invalid')
    expected_networks = {project + '_fixture': '10.245.239.2', project + '_image_downloads': '10.245.240.2'}
    declared = source.get('networks')
    require(type(declared) is dict and declared == {
                'fixture': {'ipv4_address': '10.245.239.2', 'priority': 100},
                'image_downloads': {'ipv4_address': '10.245.240.2', 'priority': 0}}
            and all(type(network['priority']) is int for network in declared.values()), 'Canonical node network priorities changed')
    require(host.get('NetworkMode') == project + '_fixture' and set(networks.get('Networks', {})) == set(expected_networks),
            'Unexpected node networks')
    require(networks.get('Ports') in (None, {}), 'Published node ports forbidden')
    for name, address in expected_networks.items():
        endpoint = networks['Networks'][name]
        require(type(endpoint) is dict, 'Network endpoint invalid')
        require(endpoint.get('IPAMConfig') == {'IPv4Address': address}, 'Network static address changed')
        aliases = endpoint.get('Aliases') or []
        require({project + '-cluster-1', 'cluster'} <= set(aliases) <= {project + '-cluster-1', 'cluster', hostname},
                'Unexpected network aliases')
        require(not endpoint.get('GlobalIPv6Address') and not endpoint.get('IPv6Gateway')
                and endpoint.get('DriverOpts') in (None, {}), 'Unexpected network configuration')
    mounts = node.get('Mounts')
    require(type(mounts) is list and len(mounts) in (4, 7), 'Unexpected node mount count')
    volumes = {}
    destinations = set()
    for mount in mounts:
        require(type(mount) is dict, 'Mount descriptor invalid')
        destination = mount.get('Destination')
        require(destination not in destinations, 'Duplicate mount destination')
        destinations.add(destination)
        require(mount.get('RW') is True and mount.get('Propagation', '') == '', 'Unexpected mount mode')
        if mount.get('Type') == 'tmpfs':
            require(destination in TMPFS and not mount.get('Name') and not mount.get('Source'), 'Unexpected tmpfs mount')
            continue
        require(mount.get('Type') == 'volume' and destination in ANONYMOUS | {'/fixture'}, 'Host bind or extra volume forbidden')
        name = mount.get('Name')
        require(type(name) is str and (name == project + '_credentials' if destination == '/fixture' else HEX.fullmatch(name)),
                'Volume name or anonymous target invalid')
        require(name not in volumes and mount.get('Driver') == 'local' and mount.get('Mode', '') in ('', 'rw', 'z'),
                'Unexpected volume driver or mode')
        volumes[name] = mount
    require({v['Destination'] for v in volumes.values()} == ANONYMOUS | {'/fixture'}, 'Incomplete node volume inventory')
    declared = config.get('Volumes') or {}
    require(set(declared) == ANONYMOUS | {'/var/lib/rancher/k3s'} and all(v == {} for v in declared.values()),
            'Pinned image volume declaration changed')
    binds = host.get('Binds') or []
    require(binds in ([], [project + '_credentials:/fixture:rw']), 'Unexpected bind declaration')
    for mount in host.get('Mounts') or []:
        require(mount.get('Type') == 'volume' and mount.get('Source') == project + '_credentials'
                and mount.get('Target') == '/fixture' and ('ReadOnly' not in mount or mount['ReadOnly'] is False)
                and not mount.get('BindOptions') and not mount.get('TmpfsOptions')
                and not (mount.get('VolumeOptions') or {}).get('DriverConfig'), 'Unexpected explicit mount declaration')
    descriptors = [v for v in objects if 'Id' not in v]
    require(len(descriptors) == len(volumes) and {v.get('Name') for v in descriptors} == set(volumes), 'Complete volume inspect set required')
    for volume in descriptors:
        name = volume['Name']
        require(volume.get('Driver') == 'local' and volume.get('Scope') == 'local' and volume.get('Options') in (None, {}),
                'Volume driver options forbidden')
        moment = timestamp(volume.get('CreatedAt'))
        require(created - 5 <= moment <= now and now - moment <= MAX_AGE, 'Volume not freshly created with node')
        require(type(volume.get('Mountpoint')) is str and volume['Mountpoint'].startswith('/')
                and volume['Mountpoint'] == volumes[name].get('Source'), 'Volume mountpoint mismatch')
        label = volume.get('Labels') or {}
        if name == project + '_credentials':
            require(set(label) == {'cloudlab.io/purpose', 'com.docker.compose.project', 'com.docker.compose.volume', 'com.docker.compose.version'}
                and label['cloudlab.io/purpose'] == PURPOSE and label['com.docker.compose.project'] == project
                and label['com.docker.compose.volume'] == 'credentials'
                and re.fullmatch(r'\d+\.\d+\.\d+', label['com.docker.compose.version']), 'Credential volume ownership mismatch')
        else:
            require(label in ({}, {'com.docker.volume.anonymous': ''}), 'Anonymous volume labels invalid')
    return {'id': container_id, 'hostname': hostname, 'project': project,
            'inspectSha256': hashlib.sha256(raw).hexdigest(), 'startupSha256': hashlib.sha256(command[0].encode()).hexdigest()}


def write_receipt(record, directory=Path('/fixture'), now=None):
    """Publish complete content exclusively via no-follow temp inode + hard link."""
    require(os.geteuid() == 0 and os.getegid() == 0, 'Root receipt writer required')
    moment = int(time.time() if now is None else now)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    pending = '.preflight-' + secrets.token_hex(16)
    created = False
    try:
        details = os.fstat(descriptor)
        require(stat.S_ISDIR(details.st_mode) and details.st_uid == 0 and details.st_gid == 0
                and stat.S_IMODE(details.st_mode) & 0o022 == 0, 'Credential directory ownership invalid')
        require(not os.listdir(descriptor), 'Credential directory must be empty; existing/consumed receipts cannot resume')
        payload = ('\n'.join([VERSION, record['id'], record['hostname'], record['project'], str(moment),
                               str(moment + TTL), record['inspectSha256']]) + '\n').encode()
        require(len(payload) <= 512, 'Receipt size invalid')
        output = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
        created = True
        try:
            info = os.fstat(output)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, 'Receipt inode invalid')
            with os.fdopen(output, 'wb', closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(output)
            os.link(pending, 'preflight.receipt', src_dir_fd=descriptor, dst_dir_fd=descriptor, follow_symlinks=False)
            os.unlink(pending, dir_fd=descriptor)
            created = False
            os.fsync(descriptor)
        finally:
            os.close(output)
        return hashlib.sha256(payload).hexdigest()
    finally:
        if created:
            os.unlink(pending, dir_fd=descriptor)
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container-id', required=True)
    args = parser.parse_args()
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    record = validate(raw, args.container_id, os.environ.get('FIXTURE_PROJECT'))
    digest = write_receipt(record)
    print(json.dumps({'preflight': 'passed', **record, 'receiptSha256': digest,
        'scope': 'trusted native inspect/start; hostname prevents replay, not Docker-admin authentication'}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, TypeError, KeyError, AttributeError, IndexError) as error:
        reason = str(error) if isinstance(error, Refusal) else type(error).__name__
        print('Local inspect/receipt preflight refused: ' + reason, file=sys.stderr)
        raise SystemExit(1) from None
