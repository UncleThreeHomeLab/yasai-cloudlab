"""Coordinated logical generations: database dump, roles and S3 objects/metadata."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import time

from automation.data import control

POLICY = json.loads((Path(__file__).resolve().parents[2] / 'platform/data/contract.json').read_text())
CONTENT_HEADERS = {'content-type', 'cache-control', 'content-disposition', 'content-encoding', 'content-language', 'expires'}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify(directory):
    if (directory / 'manifest.json').is_symlink() or (directory / 'manifest.json').stat().st_size > 16 * 1024**2:
        raise ValueError('Backup manifest exceeds its trust boundary')
    manifest = json.loads((directory / 'manifest.json').read_text())
    if manifest.get('format') != 1 or manifest.get('consistency') != 'application-roles-disabled-s3-restarted':
        raise ValueError('Unsupported application data generation')
    expected = {'manifest.json'}
    total = 0
    for record in manifest['files']:
        name = record['file']
        if not isinstance(name, str) or Path(name).name != name or name in expected:
            raise ValueError('Backup contains an invalid or duplicate file identity')
        expected.add(name)
        target = directory / name
        if target.is_symlink() or not target.is_file() or target.stat().st_size != record['bytes'] or digest(target) != record['sha256']:
            raise ValueError('Backup artifact integrity check failed')
        total += target.stat().st_size
    if total > POLICY['max_generation_bytes'] or {p.name for p in directory.iterdir()} != expected:
        raise ValueError('Backup exceeds its generation boundary')
    names = [record['key'] for record in manifest['objects']]
    if len(names) != len(set(names)) or len(names) > POLICY['max_objects']:
        raise ValueError('Backup object identities are invalid')
    if any(row['file'] not in expected for row in manifest['objects']):
        raise ValueError('Backup object references an absent artifact')
    return manifest


def discard_candidate(path, base):
    if path.parent.resolve() != base.resolve() or path.is_symlink() or not path.name.startswith('candidate-'):
        raise ValueError('Unexpected disposable candidate path')
    path.chmod(0o700)
    shutil.rmtree(path)


def capture(directory):
    if directory.exists():
        raise ValueError('Capture requires a new generation directory')
    if shutil.disk_usage(directory.parent).free < POLICY['max_generation_bytes'] * 2:
        raise RuntimeError('Application capture requires 32 GiB free staging space')
    directory.mkdir(mode=0o700)
    started = time.time()
    values = control.maintenance(True)
    try:
        database = values['database']
        if int(control.sql('SELECT pg_database_size(current_database())', database)) > POLICY['max_database_bytes']:
            raise RuntimeError('Database exceeds the selected logical backup budget')
        # RLS requires a deliberate backup policy; never silently omit protected rows.
        if control.sql("SELECT count(*) FROM pg_class WHERE relrowsecurity AND relnamespace IN (SELECT oid FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' AND nspname <> 'information_schema')", database) != '0':
            raise RuntimeError('RLS tables require a reviewed backup role policy before capture')
        client = control.s3()
        objects = list(client.objects(values['bucket']))
        if len(objects) > POLICY['max_objects'] or sum(row['size'] for row in objects) > POLICY['max_objects_bytes']:
            raise RuntimeError('Objects exceed the selected backup budget')
        with (directory / 'database.dump').open('wb') as output:
            control.postgres(['pg_dump', '-Fc', '--create', '--role=' + values['backupRole'], '-d', database], target=output, timeout=1800)
        # Passwords come from current ESO at restore. No cluster/operator superuser
        # roles or password hashes enter the portable application role inventory.
        roles = [values[key] for key in ('applicationRole', 'migrationRole', 'backupRole')]
        (directory / 'roles.sql').write_text('\n'.join(
            'CREATE ROLE ' + control.identity(role) + ' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20;'
            for role in roles) + '\n')
        extensions = json.loads(control.sql("SELECT coalesce(json_agg(json_build_object('name',extname,'version',extversion)), '[]'::json) FROM pg_extension", database))
        manifest = {'format': 1, 'consistency': 'application-roles-disabled-s3-restarted',
                    'captured_at': started, 'database': database, 'bucket': values['bucket'],
                    'roles': roles, 'extensions': extensions,
                    'postgres_version': control.sql('SHOW server_version'),
                    'objects': [], 'files': [], 'credential_restore': 'current-vault-values',
                    'scope': 'notes database and attachment bucket; telemetry excluded'}
        if control.sql("SELECT to_regclass('public.cloudlab_recovery_probe') IS NOT NULL", database) == 't':
            manifest['notes_probe'] = json.loads(control.sql('SELECT coalesce(json_agg(t ORDER BY id),\'[]\'::json) FROM public.cloudlab_recovery_probe t', database))
        for row in objects:
            name = 'object-' + hashlib.sha256(row['key'].encode()).hexdigest()
            with (directory / name).open('wb') as output:
                response = client.request('GET', values['bucket'], row['key'], target=output,
                                          limit=POLICY['max_objects_bytes'])
            if response['bytes'] != row['size']:
                raise RuntimeError('Object changed during coordinated capture')
            headers = {key.lower(): value for key, value in response['headers'].items()
                       if key.lower() in CONTENT_HEADERS or key.lower().startswith('x-amz-meta-')}
            tags = client.request('GET', values['bucket'], row['key'], query={'tagging': ''})['data'].decode()
            manifest['objects'].append({'key': row['key'], 'file': name, 'headers': headers, 'tags': tags})
        # No application key or database connection can write during this window.
        # A changed listing therefore signals another writer outside this contract.
        if objects != list(client.objects(values['bucket'])):
            raise RuntimeError('Object listing changed during coordinated capture')
        for path in sorted(directory.iterdir()):
            with path.open('rb') as stream:
                os.fsync(stream.fileno())
            manifest['files'].append({'file': path.name, 'bytes': path.stat().st_size, 'sha256': digest(path)})
        manifest['local_s3_network'] = client.counters()
        checksums = {row['key']: digest(directory / row['file']) for row in manifest['objects']}
        if any(checksums.get(row['object_key']) != row['sha256'] for row in manifest.get('notes_probe', [])):
            raise RuntimeError('Notes references do not match the captured object generation')
        manifest['capture_seconds'] = round(time.time() - started, 3)
        control.atomic(directory / 'manifest.json', manifest)
        verify(directory)
        for path in directory.iterdir():
            path.chmod(0o400)
        directory.chmod(0o500)
        return manifest
    finally:
        control.maintenance(False)


def retain_local(base, successful):
    # Only verified, completed local generations are eligible for retention.
    verify(successful)
    generations = sorted((p for p in base.iterdir() if p.is_dir() and p.name.startswith('generation-')),
                         key=lambda p: p.name, reverse=True)
    for old in generations[POLICY['local_generations']:]:
        if old == successful or old.is_symlink() or old.parent.resolve() != base.resolve():
            raise RuntimeError('Unexpected local retention target')
        old.chmod(0o700)
        for child in old.iterdir():
            child.chmod(0o600)
        shutil.rmtree(old)
