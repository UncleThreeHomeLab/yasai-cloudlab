"""Monthly encrypted application exports; replace only after an actual restore."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET

from automation.data.capture import POLICY, verify
from automation.data.s3 import S3, NS


def require_window(acceptance=False, now=None):
    now = now or datetime.now(timezone.utc)
    if not acceptance and now.day != 1:
        raise RuntimeError('Application off-site transfers and verification run on day 1 UTC only')


def environment(values):
    endpoint = urllib.parse.urlsplit(values['AWS_ENDPOINT'])
    if (endpoint.scheme != 'https' or not endpoint.hostname or not endpoint.hostname.endswith('.backblazeb2.com')
            or endpoint.username or endpoint.password or endpoint.port or endpoint.query or endpoint.fragment
            or endpoint.path not in ('', '/') or not re.fullmatch(r'[a-zA-Z0-9-]{3,63}', values['BUCKET'])):
        raise ValueError('Application exports require the existing B2 HTTPS endpoint and bucket')
    env = {key: value for key, value in os.environ.items() if not key.startswith(('AWS_', 'B2_', 'RESTIC_'))}
    for key in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'RESTIC_PASSWORD'):
        if not values.get(key):
            raise ValueError('Incomplete off-site credentials')
        env[key] = values[key]
    env['AWS_DEFAULT_REGION'] = values['REGION']
    env['RESTIC_REPOSITORY'] = 's3:' + values['AWS_ENDPOINT'].rstrip('/') + '/' + values['BUCKET'] + '/' + POLICY['remote_prefix']
    return env


class Repository:
    def __init__(self, values, acceptance=False):
        self.env = environment(values)
        self.values, self.acceptance = values, acceptance
        self.client = S3(values['AWS_ENDPOINT'], values['AWS_ACCESS_KEY_ID'], values['AWS_SECRET_ACCESS_KEY'], values['REGION'])

    def run(self, *arguments, write=False, cwd=None, missing_ok=False):
        require_window(self.acceptance)
        command = ['restic', '--no-cache'] + ([] if write else ['--no-lock']) + list(arguments)
        result = subprocess.run(command, env=self.env, cwd=cwd, capture_output=True, text=True, timeout=7200)
        if missing_ok and result.returncode == 10:
            return None
        if result.returncode:
            raise RuntimeError('Application restic operation failed: ' + arguments[0] + '; previous generation retained')
        return result.stdout

    def snapshots(self):
        rows = json.loads(self.run('snapshots', '--json'))
        if any('cloudlab-application-data' not in row.get('tags', []) for row in rows):
            raise RuntimeError('Application repository contains unrelated snapshots')
        return rows

    def retrieve(self, snapshot, directory):
        rows = [json.loads(line) for line in self.run('ls', snapshot, '--json').splitlines()]
        files = [row for row in rows if row.get('type') == 'file']
        if (any(row.get('type') not in (None, 'file') and not (row.get('type') == 'dir' and row.get('path') == '/') for row in rows)
                or not files or any(not isinstance(row.get('size'), int) or row['size'] < 0 for row in files)
                or sum(row['size'] for row in files) > POLICY['max_generation_bytes'] + 16 * 1024**2
                or any(not re.fullmatch(r'/(?:database\.dump|roles\.sql|manifest\.json|object-[a-f0-9]{64})', row['path']) for row in files)):
            raise RuntimeError('Off-site snapshot exceeds its restore scope')
        self.run('restore', snapshot, '--target', str(directory), '--verify')
        return verify(directory)

    def cleanup_history(self):
        require_window(self.acceptance)
        bucket, prefix = self.values['BUCKET'], POLICY['remote_prefix']
        query, rows = {'versions': '', 'prefix': prefix}, []
        for _ in range(10000):
            root = ET.fromstring(self.client.request('GET', bucket, query=query)['data'])
            for kind in ('Version', 'DeleteMarker'):
                for entry in root.findall('s:' + kind, NS):
                    key = entry.findtext('s:Key', namespaces=NS)
                    if not key or not key.startswith(prefix):
                        raise RuntimeError('B2 listing escaped the application prefix')
                    rows.append({'key': key, 'version': entry.findtext('s:VersionId', namespaces=NS), 'kind': kind,
                                 'latest': entry.findtext('s:IsLatest', namespaces=NS) == 'true',
                                 'size': int(entry.findtext('s:Size', default='0', namespaces=NS))})
            if root.findtext('s:IsTruncated', namespaces=NS) != 'true':
                break
            marker = root.findtext('s:NextKeyMarker', namespaces=NS)
            version = root.findtext('s:NextVersionIdMarker', namespaces=NS)
            if not marker or (marker, version) == (query.get('key-marker'), query.get('version-id-marker')):
                raise RuntimeError('B2 version pagination did not advance')
            query.update({'key-marker': marker, 'version-id-marker': version})
        else:
            raise RuntimeError('B2 version listing exceeds its bound')
        for row in rows:
            if row['kind'] == 'Version' and not row['latest']:
                require_window(self.acceptance)
                self.client.request('DELETE', bucket, row['key'], query={'versionId': row['version']})
        for row in rows:
            if row['kind'] == 'DeleteMarker':
                require_window(self.acceptance)
                self.client.request('DELETE', bucket, row['key'], query={'versionId': row['version']})
        query = {'uploads': '', 'prefix': prefix}
        for _ in range(10000):
            require_window(self.acceptance)
            root = ET.fromstring(self.client.request('GET', bucket, query=query)['data'])
            for entry in root.findall('s:Upload', NS):
                key = entry.findtext('s:Key', namespaces=NS)
                upload = entry.findtext('s:UploadId', namespaces=NS)
                if not key or not key.startswith(prefix) or not upload:
                    raise RuntimeError('B2 multipart listing escaped the application prefix')
                self.client.request('DELETE', bucket, key, query={'uploadId': upload})
            if root.findtext('s:IsTruncated', namespaces=NS) != 'true':
                break
            marker = root.findtext('s:NextKeyMarker', namespaces=NS)
            upload = root.findtext('s:NextUploadIdMarker', namespaces=NS)
            if not marker or (marker, upload) == (query.get('key-marker'), query.get('upload-id-marker')):
                raise RuntimeError('B2 multipart pagination did not advance')
            query.update({'key-marker': marker, 'upload-id-marker': upload})
        else:
            raise RuntimeError('B2 multipart inventory exceeds its bound')
        return sum(row['size'] for row in rows if row['kind'] == 'Version' and row['latest'])

    def export(self, directory, restore_gate):
        manifest = verify(directory)
        if self.run('cat', 'config', missing_ok=True) is None:
            self.run('init', '--repository-version', '2', write=True)
        old = self.snapshots()
        # Resume a failed gate before uploading again; no accumulating candidates
        # and no deletion of the previous good generation on a failed retry.
        pending = [row for row in old if 'verified' not in row.get('tags', [])]
        if len(pending) > 1:
            raise RuntimeError('Unexpected multiple pending application generations; preserve for review')
        if pending:
            self.run('check', '--read-data', write=True)
            with tempfile.TemporaryDirectory(prefix='cloudlab-data-retry-', dir=directory.parent) as temporary:
                self.retrieve(pending[0]['id'], Path(temporary))
                if not restore_gate(Path(temporary)).get('restored'):
                    raise RuntimeError('Pending restore gate failed; previous generation retained')
            self.run('tag', '--add', 'verified', pending[0]['id'], write=True)
        previous = [row for row in self.snapshots() if 'verified' in row.get('tags', [])]
        generation = 'generation-' + str(manifest['captured_at'])
        files = [row['file'] for row in manifest['files']] + ['manifest.json']
        output = self.run('backup', *files, '--host', 'cloudlab-application-data', '--tag', 'cloudlab-application-data',
                          '--tag', generation, '--json', write=True, cwd=directory)
        summary = next(json.loads(row) for row in output.splitlines()
                       if row.startswith('{') and json.loads(row).get('message_type') == 'summary')
        candidate = summary['snapshot_id']
        self.run('check', '--read-data', write=True)
        with tempfile.TemporaryDirectory(prefix='cloudlab-data-retrieval-', dir=directory.parent) as temporary:
            retrieved = Path(temporary)
            recovered = self.retrieve(candidate, retrieved)
            if recovered != manifest:
                raise RuntimeError('Off-site generation differs from the immutable local source')
            proof = restore_gate(retrieved)
        if not proof.get('restored'):
            raise RuntimeError('Off-site restore gate did not pass; previous generation retained')
        retained = {row['id'] for row in self.snapshots()}
        if any(row['id'] not in retained for row in previous):
            raise RuntimeError('Previous good generation disappeared before the replacement gate')
        self.run('tag', '--add', 'verified', candidate, write=True)
        rows = self.snapshots()
        verified = [row for row in rows if generation in row.get('tags', []) and 'verified' in row.get('tags', [])]
        if len(verified) != 1:
            raise RuntimeError('Cannot identify the verified application generation')
        keep = verified[0]['id']
        obsolete = [row['id'] for row in rows if row['id'] != keep]
        if obsolete:
            self.run('forget', *obsolete, write=True)
        self.run('prune', write=True)
        size = self.cleanup_history()
        self.run('check', '--read-data', write=True)
        if len(self.snapshots()) != 1:
            raise RuntimeError('Monthly retention did not leave exactly one generation')
        return {'captured_at': manifest['captured_at'], 'verified_at': datetime.now(timezone.utc).timestamp(),
                'snapshot': keep, 'previous_preserved_until_verified': bool(previous), 'retention_complete': True,
                'retained_generations': 1, 'repository_bytes': size,
                'backup_added_bytes': summary.get('data_added', 0),
                'backup_added_packed_bytes': summary.get('data_added_packed', 0),
                'wire_bytes_measured': False,
                'restore': proof, 'explicit_acceptance_exception': self.acceptance,
                'b2_cleanup_network': self.client.counters(), 'b2_transfer_network': 'restic backup, full check, retrieval, retention and final check'}
