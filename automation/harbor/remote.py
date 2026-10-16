"""Monthly native Longhorn export; retain the previous generation until restored."""
import json
from pathlib import Path
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET

from automation.data.remote import require_window, volume_prefix, storage_policy
from automation.data.s3 import S3, NS
from automation.harbor import recovery
from automation.mesh.kube import get, kube, wait


def policy():
    return json.loads((Path(__file__).resolve().parents[2] / 'platform/harbor/policy.json').read_text())


class Repository:
    def __init__(self):
        from automation.data.control import secret
        self.values = secret('data-offsite')
        endpoint = urllib.parse.urlsplit(self.values['AWS_ENDPOINT'])
        if (endpoint.scheme != 'https' or not endpoint.hostname or not endpoint.hostname.endswith('.backblazeb2.com')
                or endpoint.path not in ('', '/') or endpoint.query or endpoint.fragment or endpoint.username
                or endpoint.password or endpoint.port or not re.fullmatch(r'[a-zA-Z0-9-]{3,63}', self.values['BUCKET'])):
            raise ValueError('Harbor exports require the existing B2 HTTPS target')
        self.client = S3(self.values['AWS_ENDPOINT'], self.values['AWS_ACCESS_KEY_ID'],
                         self.values['AWS_SECRET_ACCESS_KEY'], self.values['REGION'])

    def request(self, method, key='', **kwargs):
        require_window()
        return self.client.request(method, self.values['BUCKET'], key, **kwargs)

    def manifests(self):
        prefix = policy()['remote_prefix']
        root = ET.fromstring(self.request('GET', query={'list-type': '2', 'prefix': prefix, 'max-keys': '32'})['data'])
        if root.findtext('s:IsTruncated', namespaces=NS) == 'true':
            raise RuntimeError('Harbor recovery metadata exceeds its bounded generation inventory')
        result = []
        for row in root.findall('s:Contents', NS):
            key = row.findtext('s:Key', namespaces=NS)
            if not key or not re.fullmatch(re.escape(prefix) + r'harbor-[a-f0-9]{24}[.]json', key):
                raise RuntimeError('Unknown object in the Harbor recovery prefix; no retention')
            manifest = recovery.validate(json.loads(self.request('GET', key)['data']))
            if not manifest.get('verified_at') or key != prefix + manifest['generation'] + '.json':
                raise RuntimeError('Unverified Harbor recovery metadata')
            result.append(manifest)
        return result

    def validate_url(self, row):
        url = urllib.parse.urlsplit(row['url'])
        if (url.scheme != 's3' or url.netloc != self.values['BUCKET'] + '@' + self.values['REGION'] or
                url.path != '/' + storage_policy()['prefix'] or url.fragment or
                urllib.parse.parse_qs(url.query) != {'volume': [row['volume']], 'backup': [row['snapshot']]}):
            raise ValueError('Harbor recovery URL escaped its recorded volume and native target')

    def backup(self, row):
        obj = get('backups.longhorn.io', row['snapshot'], 'longhorn-system')
        if obj and (obj['metadata'].get('labels', {}).get('cloudlab.io/owner') != recovery.OWNER or
                    obj['metadata'].get('labels', {}).get('backup-volume') != row['volume'] or
                    obj['spec']['snapshotName'] != row['snapshot']):
            raise RuntimeError('Harbor backup identity changed; no retention or adoption')
        return obj

    def upload(self, manifest):
        recovery.validate(manifest)
        if sum(row['actual_bytes'] for row in manifest['volumes'].values()) > policy()['max_generation_bytes']:
            raise RuntimeError('Harbor export exceeds its storage budget; previous generation retained')
        root = ET.fromstring(self.request('GET', query={'encryption': ''})['data'])
        if {entry.text for entry in root.iter() if entry.tag.split('}')[-1] == 'SSEAlgorithm'} != {'AES256'}:
            raise RuntimeError('Harbor backups require accepted B2-managed AES256 encryption')
        for row in manifest['volumes'].values():
            require_window(reserve=3600)
            if not self.backup(row):
                kube('create', '-f', '-', document={'apiVersion': 'longhorn.io/v1beta2', 'kind': 'Backup',
                    'metadata': {'name': row['snapshot'], 'namespace': 'longhorn-system', 'labels': dict(
                        recovery.LABEL, **{'backup-volume': row['volume'], 'backup-target': 'default'})},
                    'spec': {'snapshotName': row['snapshot'], 'backupMode': 'incremental', 'backupBlockSize': '2097152'}})
            def complete():
                status = self.backup(row).get('status', {})
                if status.get('error') or status.get('state') == 'Error':
                    raise RuntimeError('Harbor export failed; previous generation retained')
                return status.get('url') if status.get('state') == 'Completed' else False
            row['url'] = wait(complete, 'monthly Harbor volume export', timeout=3600)
            self.validate_url(row)
            recovery.atomic(recovery.BASE / 'pending-volume.json', manifest)

    def versions(self, prefix):
        query = {'versions': '', 'prefix': prefix}
        for _ in range(10000):
            root = ET.fromstring(self.request('GET', query=query)['data'])
            for kind in ('Version', 'DeleteMarker'):
                for entry in root.findall('s:' + kind, NS):
                    key, version = entry.findtext('s:Key', namespaces=NS), entry.findtext('s:VersionId', namespaces=NS)
                    if not key or not key.startswith(prefix) or not version:
                        raise RuntimeError('B2 versions escaped the recorded Harbor prefix')
                    yield {'key': key, 'version': version, 'kind': kind,
                           'latest': entry.findtext('s:IsLatest', namespaces=NS) == 'true'}
            if root.findtext('s:IsTruncated', namespaces=NS) != 'true':
                return
            marker = root.findtext('s:NextKeyMarker', namespaces=NS), root.findtext('s:NextVersionIdMarker', namespaces=NS)
            if not marker[0] or marker == (query.get('key-marker'), query.get('version-id-marker')):
                raise RuntimeError('Harbor B2 version pagination did not advance')
            query.update({'key-marker': marker[0], 'version-id-marker': marker[1]})
        raise RuntimeError('Harbor B2 versions exceed the bounded retention inventory')

    def prune_versions(self, prefix):
        rows = list(self.versions(prefix))
        for kind in ('Version', 'DeleteMarker'):
            for row in rows:
                if row['kind'] == kind and (kind == 'DeleteMarker' or not row['latest']):
                    self.request('DELETE', row['key'], query={'versionId': row['version']})

    def accept(self, manifest, proof):
        if not proof.get('restored') or not proof.get('offsite_reads'):
            raise RuntimeError('Actual off-site Harbor restore must pass before retention')
        pending = recovery.BASE / 'retention-pending.json'
        previous = [row for row in self.manifests() if row['generation'] != manifest['generation']]
        if pending.exists():
            plan = json.loads(pending.read_text())
            if plan['generation'] != manifest['generation'] or plan['volumes'] != manifest['volumes']:
                raise RuntimeError('Harbor retention receipt differs from its verified generation')
        else:
            for old in previous:
                for row in old['volumes'].values():
                    self.validate_url(row)
                    obj = self.backup(row)
                    if not obj or obj.get('status', {}).get('url') != row['url']:
                        raise RuntimeError('Previous Harbor backup must be identified before retention')
            plan = {'generation': manifest['generation'], 'volumes': manifest['volumes'], 'previous': previous}
            recovery.atomic(pending, plan)
        manifest.update(verified_at=time.time(), restore=proof)
        key = policy()['remote_prefix'] + manifest['generation'] + '.json'
        self.request('PUT', key, data=json.dumps(manifest, sort_keys=True).encode(),
                     headers={'content-type': 'application/json', 'x-amz-server-side-encryption': 'AES256'})
        if json.loads(self.request('GET', key)['data']) != manifest:
            raise RuntimeError('Harbor off-site metadata readback differs; previous generation retained')
        for old in plan['previous']:
            for row in old['volumes'].values():
                self.validate_url(row)
                obj = self.backup(row)
                if obj:
                    if obj.get('status', {}).get('url') != row['url']:
                        raise RuntimeError('Previous Harbor backup URL changed; retention stopped')
                    require_window()
                    kube('delete', 'backups.longhorn.io', row['snapshot'], '-n', 'longhorn-system',
                         '--wait=true', '--timeout=1800s', timeout=1830)
            self.request('DELETE', policy()['remote_prefix'] + old['generation'] + '.json')
        for prefix in {volume_prefix(row['volume']) for generation in plan['previous'] + [manifest]
                       for row in generation['volumes'].values()} | {policy()['remote_prefix']}:
            self.prune_versions(prefix)
        if [row['generation'] for row in self.manifests()] != [manifest['generation']]:
            raise RuntimeError('Harbor retention has not converged to one verified generation')
        result = {'generation': manifest['generation'], 'captured_at': manifest['captured_at'],
                  'verified_at': manifest['verified_at'], 'retained_generations': 1, 'retention_complete': True,
                  'restore': proof, 'encryption': 'B2-managed AES256', 'network': self.client.counters()}
        recovery.atomic(recovery.BASE / 'monthly-receipt.json', result)
        pending.unlink()
        return result
