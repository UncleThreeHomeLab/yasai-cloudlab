"""Prove disposable service credential scope and retained SQL/S3 data."""
import base64
import hashlib
import re

from playbooks.data.files import control
from playbooks.data.files.s3 import S3, S3Error
from playbooks.data.files.verify import NAMESPACE, OWNER, pod_query, sql_client
from playbooks.istio.files.kube import get, kube

BODY = b'cloudlab retained service data\n'
KEY = 'cloudlab-proof/retained-service-data'


def fixture(entry):
    name = entry['definition']['name']
    if (not re.fullmatch(r'fixture-[a-f0-9]{12}', name) or entry['approval']['name'] != name or
            entry['approval']['namespace'] != 'cloudlab-app-' + name or
            set(entry['definition']['data']) != {'database', 'bucket'}):
        raise ValueError('Data proof requires its exact disposable service scope')
    return name


def run(entry):
    name = fixture(entry)
    definition = entry['definition']
    values = control.settings()
    request = next((row for row in values['serviceRequests'] if row['service'] == name), None)
    if not request: raise RuntimeError('Disposable data request is not reconciled')
    database = request['database']
    if database['name'] != definition['data']['database']['name']:
        raise RuntimeError('Disposable database scope differs from its definition')
    namespace = entry['approval']['namespace']
    secret = get('secret', definition['data']['database']['credentialReference'], namespace)
    credentials = {key: base64.b64decode(value, validate=True).decode() for key, value in secret['data'].items()}
    if set(credentials) != {'username', 'password'} or credentials['username'] != database['applicationRole']:
        raise RuntimeError('Disposable SQL credentials exceed their application scope')
    with control.locked() as owner:
        control.sql('SET ROLE ' + control.identity(database['migrationRole']) +
                    '; CREATE TABLE IF NOT EXISTS public.cloudlab_service_probe(id integer PRIMARY KEY, sha256 text NOT NULL);', database['name'])
        control.native_repair(owner, 'sql')
        sql_client({'database': database['name']}, credentials)
        try:
            digest = hashlib.sha256(BODY).hexdigest()
            query = "INSERT INTO public.cloudlab_service_probe VALUES (1, '" + digest + "') ON CONFLICT(id) DO NOTHING; SELECT sha256 FROM public.cloudlab_service_probe WHERE id=1; SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid();"
            result = pod_query([], query)
            if result.returncode or result.stdout.splitlines()[-2:] != [digest, 't']:
                raise RuntimeError('Scoped service SQL data or native TLS proof failed')
            for args, statement in ((['env', 'PGDATABASE=' + values['database']], 'SELECT 1;'),
                                    (['env', 'PGDATABASE=postgres'], 'SELECT 1;'),
                                    (['env', 'PGSSLMODE=disable'], 'SELECT 1;'),
                                    ([], 'CREATE TABLE forbidden_by_scope(id integer);')):
                if pod_query(args, statement).returncode == 0:
                    raise RuntimeError('Service SQL role escaped its approved scope')
        finally:
            obj = get('namespace', NAMESPACE)
            if obj and obj['metadata'].get('labels', {}).get('cloudlab.io/fixture') == OWNER:
                kube('delete', 'namespace', NAMESPACE, '--wait=true', '--timeout=120s')
        secret = get('secret', definition['data']['bucket']['credentialReference'], namespace)
        credentials = {key: base64.b64decode(value, validate=True).decode() for key, value in secret['data'].items()}
        if set(credentials) != {'BUCKET', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY', 'ENDPOINT', 'REGION'} or credentials['BUCKET'] != request['bucket']['name']:
            raise RuntimeError('Disposable S3 credentials exceed their application scope')
        client = S3(credentials['ENDPOINT'], credentials['ACCESS_KEY_ID'], credentials['SECRET_ACCESS_KEY'])
        try:
            actual = client.request('GET', credentials['BUCKET'], KEY)['data']
            if actual != BODY: raise RuntimeError('Retained service object changed; overwrite refused')
        except S3Error as error:
            if error.status != 404: raise
            client.request('PUT', credentials['BUCKET'], KEY, data=BODY)
        if client.request('GET', credentials['BUCKET'], KEY)['data'] != BODY:
            raise RuntimeError('Scoped retained S3 object differs')
        try:
            client.request('GET', values['bucket'], query={'list-type': '2'})
            raise RuntimeError('Service S3 key can list another application bucket')
        except S3Error as error:
            if error.status != 403: raise
    return {'sql_native_tls': True, 'sql_and_s3_cross_scope_denied': True,
            'persistent_test_data': True, 'existing_data_overwritten': False}
