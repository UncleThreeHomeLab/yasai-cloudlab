"""Recovery inventories and coordinated cold Longhorn snapshots, not dumps."""
import json
from pathlib import Path
import re
import time
import uuid

from automation.data import control, volumes

POLICY = json.loads((Path(__file__).resolve().parents[2] / 'platform/data/contract.json').read_text())
CONTENT_HEADERS = {'content-type', 'cache-control', 'content-disposition', 'content-encoding', 'content-language', 'expires'}


def verify(manifest):
    if (not isinstance(manifest, dict) or manifest.get('format') != 2
            or manifest.get('consistency') != 'all-writers-stopped'
            or manifest.get('captured') is not True):
        raise ValueError('Incomplete or unsupported cold application generation')
    volumes.validate_sources(manifest)
    if len(manifest['objects']) > POLICY['max_objects'] or len({r['key'] for r in manifest['objects']}) != len(manifest['objects']):
        raise ValueError('Invalid object inventory')
    if any(not re.fullmatch('[a-f0-9]{64}', r['sha256']) or r['bytes'] < 0 for r in manifest['objects']):
        raise ValueError('Invalid object checksum inventory')
    if sum(r['bytes'] for r in manifest['objects']) > POLICY['max_objects_bytes']:
        raise ValueError('Object inventory exceeds the backup budget')
    for role in manifest['roles']:
        control.identity(role)
    control.identity(manifest['database'])
    if len(manifest['roles']) != 3 or len(set(manifest['roles'])) != 3:
        raise ValueError('Expected three distinct recovery roles')
    return manifest


def capture():
    started = time.time()
    checkpoint = control.BASE / 'pending-volume.json'
    if checkpoint.exists():
        raise RuntimeError('A previous generation must be resumed before another capture')
    generation = 'data-' + uuid.uuid4().hex[:24]
    manifest = {'format': 2, 'generation': generation, 'captured_at': started,
                'consistency': 'all-writers-stopped', 'captured': False,
                'volumes': volumes.inventory(), 'objects': []}
    if sum(r['actual_bytes'] for r in manifest['volumes'].values()) > POLICY['max_generation_bytes']:
        raise RuntimeError('Application volume data exceeds the monthly transfer budget')
    for component, row in manifest['volumes'].items():
        row['snapshot'] = generation + '-' + component
    control.atomic(checkpoint, manifest)
    try:
        values = control.maintenance(True)
        manifest.update(database=values['database'], bucket=values['bucket'],
                        roles=[values[k] for k in ('applicationRole', 'migrationRole', 'backupRole')])
        if int(control.sql('SELECT pg_database_size(current_database())', values['database'])) > POLICY['max_database_bytes']:
            raise RuntimeError('Database exceeds the selected backup budget')
        manifest['extensions'] = json.loads(control.sql("SELECT coalesce(json_agg(json_build_object('name',extname,'version',extversion)), '[]'::json) FROM pg_extension", values['database']))
        manifest['postgres_version'] = control.sql('SHOW server_version')
        if control.sql("SELECT to_regclass('public.cloudlab_recovery_probe') IS NOT NULL", values['database']) == 't':
            manifest['notes_probe'] = json.loads(control.sql("SELECT coalesce(json_agg(t ORDER BY id),'[]'::json) FROM public.cloudlab_recovery_probe t", values['database']))
        client = control.s3()
        total = 0
        for row in client.objects(values['bucket']):
            total += row['size']
            if len(manifest['objects']) >= POLICY['max_objects'] or total > POLICY['max_objects_bytes']:
                raise RuntimeError('Objects exceed the selected backup budget')
            # Stream checksums only; no second copy of object data is staged.
            with open('/dev/null', 'wb') as sink:
                response = client.request('GET', values['bucket'], row['key'], target=sink, limit=POLICY['max_objects_bytes'])
            if response['bytes'] != row['size']:
                raise RuntimeError('Object changed during coordinated capture')
            headers = {k.lower(): v for k, v in response['headers'].items()
                       if k.lower() in CONTENT_HEADERS or k.lower().startswith('x-amz-meta-')}
            tags = client.request('GET', values['bucket'], row['key'], query={'tagging': ''})['data'].decode()
            manifest['objects'].append({'key': row['key'], 'sha256': response['sha256'],
                                        'bytes': response['bytes'], 'headers': headers, 'tags': tags})
        checksums = {r['key']: r['sha256'] for r in manifest['objects']}
        if any(checksums.get(r['object_key']) != r['sha256'] for r in manifest.get('notes_probe', [])):
            raise RuntimeError('Notes references do not match the object generation')
        volumes.stop()
        control.atomic(checkpoint, manifest)
        volumes.snapshots(manifest)
        manifest['captured'] = True
        manifest['capture_seconds'] = round(time.time() - started, 3)
        manifest['local_s3_network'] = client.counters()
        verify(manifest)
        control.atomic(checkpoint, manifest)
        return manifest
    finally:
        volumes.resume()
