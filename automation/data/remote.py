"""Monthly Longhorn exports and scoped B2 metadata/retention; no restic data copy."""
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import urllib.parse
import xml.etree.ElementTree as ET

from automation.data import control, volumes
from automation.data.capture import POLICY, verify
from automation.data.s3 import S3, NS, S3Error
from automation.mesh.kube import get, kube, wait


def require_window(acceptance=False, now=None, reserve=0):
    now = now or datetime.now(timezone.utc)
    remaining = 86400 - (now.hour * 3600 + now.minute * 60 + now.second)
    if not acceptance and (now.day != 1 or remaining <= reserve):
        raise RuntimeError('Application off-site transfers and verification run on day 1 UTC only')


def storage_policy():
    path = control.ROOT / 'platform/storage/longhorn-backup/policy.json'
    if not path.exists():
        path = Path('/var/lib/cloudlab/longhorn/backup-policy.json')
    return json.loads(path.read_text())


def volume_prefix(volume):
    if not re.fullmatch(r'pvc-[a-f0-9-]{36}', volume):
        raise ValueError('Unexpected application backup volume')
    checksum = hashlib.sha512(volume.encode()).hexdigest()
    return storage_policy()['prefix'] + 'backupstore/volumes/' + checksum[:2] + '/' + checksum[2:4] + '/' + volume + '/'


class Repository:
    def __init__(self, values, acceptance=False):
        endpoint = urllib.parse.urlsplit(values['AWS_ENDPOINT'])
        if (endpoint.scheme != 'https' or not endpoint.hostname or not endpoint.hostname.endswith('.backblazeb2.com')
                or endpoint.username or endpoint.password or endpoint.port or endpoint.query or endpoint.fragment
                or endpoint.path not in ('', '/') or not re.fullmatch(r'[a-zA-Z0-9-]{3,63}', values['BUCKET'])):
            raise ValueError('Application backups require the existing B2 HTTPS endpoint and bucket')
        self.values, self.acceptance = values, acceptance
        self.client = S3(values['AWS_ENDPOINT'], values['AWS_ACCESS_KEY_ID'], values['AWS_SECRET_ACCESS_KEY'], values['REGION'])

    def request(self, method, key='', **kwargs):
        require_window(self.acceptance)
        return self.client.request(method, self.values['BUCKET'], key, **kwargs)

    def encryption(self):
        root = ET.fromstring(self.request('GET', query={'encryption': ''})['data'])
        if {e.text for e in root.iter() if e.tag.split('}')[-1] == 'SSEAlgorithm'} != {'AES256'}:
            raise RuntimeError('Longhorn backups require accepted B2-managed AES256 encryption')

    def manifests(self):
        require_window(self.acceptance)
        result = []
        for row in self.client.objects(self.values['BUCKET'], POLICY['remote_prefix']):
            if not re.fullmatch(re.escape(POLICY['remote_prefix']) + r'data-[a-f0-9]{24}\.json', row['key']):
                raise RuntimeError('Unexpected object in the coordinated recovery metadata prefix')
            manifest = verify(json.loads(self.request('GET', row['key'])['data']))
            if manifest['generation'] + '.json' != row['key'].split('/')[-1] or not manifest.get('verified_at'):
                raise RuntimeError('Unverified recovery metadata')
            result.append(manifest)
        return result

    def latest(self):
        rows = self.manifests()
        if not rows:
            raise RuntimeError('No verified Longhorn application generation is available')
        return max(rows, key=lambda row: row['captured_at'])

    def validate_url(self, row):
        url = urllib.parse.urlsplit(row['url'])
        expected = self.values['BUCKET'] + '@' + self.values['REGION']
        if (url.scheme != 's3' or url.netloc != expected or url.path != '/' + storage_policy()['prefix']
                or url.fragment or urllib.parse.parse_qs(url.query) != {'volume': [row['volume']], 'backup': [row['snapshot']]}):
            raise ValueError('Longhorn recovery URL escaped its declared volume and target')

    def upload(self, manifest):
        verify(manifest)
        self.encryption()
        for row in manifest['volumes'].values():
            require_window(self.acceptance, reserve=3600)
            current = get('backups.longhorn.io', row['snapshot'], volumes.LH)
            if current and (current['metadata'].get('labels', {}).get('cloudlab.io/owner') != volumes.OWNER
                            or current['spec']['snapshotName'] != row['snapshot']):
                raise RuntimeError('Backup identity is not owned by this generation')
            if not current:
                kube('create', '-f', '-', document={'apiVersion': 'longhorn.io/v1beta2', 'kind': 'Backup',
                     'metadata': {'name': row['snapshot'], 'namespace': volumes.LH,
                                  'labels': {'cloudlab.io/owner': volumes.OWNER,
                                             'backup-volume': row['volume'], 'backup-target': 'default'}},
                     'spec': {'snapshotName': row['snapshot'], 'backupMode': 'incremental',
                              'backupBlockSize': '2097152'}})
            def completed():
                status = get('backups.longhorn.io', row['snapshot'], volumes.LH).get('status', {})
                if status.get('error') or status.get('state') == 'Error':
                    raise RuntimeError('Longhorn application upload failed; previous generation retained')
                return status.get('url') if status.get('state') == 'Completed' else False
            row['url'] = wait(completed, 'Longhorn application upload', timeout=3600)
            self.validate_url(row)
            control.atomic(control.BASE / 'pending-volume.json', manifest)
        return manifest

    def read_blocks(self, manifest):
        # This independent reader uses only B2 and the pinned Longhorn format.
        # Restore verification separately boots all four downloaded volumes.
        verify(manifest)
        count, stored = 0, 0
        for row in manifest['volumes'].values():
            self.validate_url(row)
            prefix = volume_prefix(row['volume'])
            config = json.loads(self.request('GET', prefix + 'backups/backup_' + row['snapshot'] + '.cfg')['data'])
            if config.get('VolumeName') != row['volume'] or config.get('SnapshotName') != row['snapshot']:
                raise RuntimeError('Longhorn backup metadata differs from the coordinated generation')
            if config.get('CompressionMethod') != 'gzip':
                raise RuntimeError('Independent reader requires the declared gzip Longhorn backup format')
            blocks = config.get('Blocks', [])
            if not blocks or len(blocks) > 32768:
                raise RuntimeError('Unexpected Longhorn backup block inventory')
            seen = set()
            for block in blocks:
                checksum = block['BlockChecksum']
                if not re.fullmatch('[a-f0-9]{64}', checksum):
                    raise ValueError('Invalid Longhorn block checksum')
                if checksum in seen:
                    continue
                seen.add(checksum)
                key = prefix + 'blocks/' + checksum[:2] + '/' + checksum[2:4] + '/' + checksum + '.blk'
                response = self.request('GET', key, limit=32 * 1024**2)
                with gzip.GzipFile(fileobj=io.BytesIO(response['data'])) as stream:
                    data = stream.read(17 * 1024**2)
                    if len(data) > 16 * 1024**2 or hashlib.sha512(data).hexdigest()[:64] != checksum:
                        raise RuntimeError('Longhorn backup block checksum differs')
                count += 1
                stored += response['bytes']
                if stored > POLICY['max_generation_bytes']:
                    raise RuntimeError('Physical backup exceeds the monthly transfer budget')
        return {'verified_blocks': count, 'compressed_bytes_read': stored, 'local_backup_files': 0}

    def versions(self, prefix):
        query = {'versions': '', 'prefix': prefix}
        for _ in range(10000):
            root = ET.fromstring(self.request('GET', query=query)['data'])
            for kind in ('Version', 'DeleteMarker'):
                for entry in root.findall('s:' + kind, NS):
                    key = entry.findtext('s:Key', namespaces=NS)
                    version = entry.findtext('s:VersionId', namespaces=NS)
                    if not key or not key.startswith(prefix) or not version:
                        raise RuntimeError('B2 version listing escaped the approved prefix')
                    yield {'key': key, 'version': version, 'kind': kind,
                           'latest': entry.findtext('s:IsLatest', namespaces=NS) == 'true'}
            if root.findtext('s:IsTruncated', namespaces=NS) != 'true':
                return
            marker = (root.findtext('s:NextKeyMarker', namespaces=NS), root.findtext('s:NextVersionIdMarker', namespaces=NS))
            if not marker[0] or marker == (query.get('key-marker'), query.get('version-id-marker')):
                raise RuntimeError('B2 version pagination did not advance')
            query.update({'key-marker': marker[0], 'version-id-marker': marker[1]})
        raise RuntimeError('B2 version listing exceeds its bound')

    def cleanup_versions(self, prefix, *, remove_all=False):
        rows = list(self.versions(prefix))
        removed = 0
        # Delete hidden file data before markers; never resurrect an obsolete object.
        for kind in ('Version', 'DeleteMarker'):
            for row in rows:
                if row['kind'] == kind and (remove_all or kind == 'DeleteMarker' or not row['latest']):
                    self.request('DELETE', row['key'], query={'versionId': row['version']})
                    removed += 1
        return removed

    def accept(self, manifest, proof):
        if not proof.get('restored'):
            raise RuntimeError('Restore gate failed; previous generation retained')
        previous = self.manifests()
        manifest['verified_at'] = datetime.now(timezone.utc).timestamp()
        manifest['restore'] = proof
        key = POLICY['remote_prefix'] + manifest['generation'] + '.json'
        self.request('PUT', key, data=json.dumps(manifest, sort_keys=True).encode(),
                     headers={'content-type': 'application/json', 'x-amz-server-side-encryption': 'AES256'})
        if json.loads(self.request('GET', key)['data']) != manifest:
            raise RuntimeError('Off-site recovery metadata readback differs; preserve previous generation')
        for old in previous:
            if old['generation'] == manifest['generation']:
                continue
            for row in old['volumes'].values():
                self.validate_url(row)
                require_window(self.acceptance)
                current = get('backups.longhorn.io', row['snapshot'], volumes.LH)
                if not current:
                    try:
                        self.request('GET', volume_prefix(row['volume']) + 'backups/backup_' + row['snapshot'] + '.cfg')
                    except S3Error as error:
                        if error.status != 404:
                            raise
                    else:
                        raise RuntimeError('Previous backup CR is missing while remote data remains')
                if current and (current['metadata'].get('labels', {}).get('cloudlab.io/owner') != volumes.OWNER
                                or current['spec']['snapshotName'] != row['snapshot']
                                or current.get('status', {}).get('url') != row['url']):
                    raise RuntimeError('Previous backup identity changed before retention')
                if current:
                    kube('delete', 'backups.longhorn.io', row['snapshot'], '-n', volumes.LH,
                         '--wait=true', '--timeout=1800s', timeout=1830)
            self.request('DELETE', POLICY['remote_prefix'] + old['generation'] + '.json')
        for prefix in {volume_prefix(r['volume']) for m in previous + [manifest] for r in m['volumes'].values()}:
            self.cleanup_versions(prefix)
        self.cleanup_versions(POLICY['remote_prefix'])
        # The user requested one replacement path. Retire only the legacy app
        # prefix after the new physical generation passed its full restore gate.
        removed_legacy = self.cleanup_versions(POLICY['legacy_remote_prefix'], remove_all=True)
        return {'captured_at': manifest['captured_at'], 'verified_at': manifest['verified_at'],
                'generation': manifest['generation'], 'backend': 'longhorn', 'restore': proof,
                'retained_generations': 1, 'retention_complete': True,
                'removed_legacy_remote_versions': removed_legacy,
                'previous_preserved_until_verified': bool(previous),
                'explicit_acceptance_exception': self.acceptance,
                'encryption': 'B2-managed AES256', 'wire_bytes_measured': False,
                'metadata_and_verification_network': self.client.counters()}
