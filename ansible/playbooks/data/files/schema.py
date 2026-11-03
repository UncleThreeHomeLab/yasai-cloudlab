"""Explicit application schema changes using the existing scoped migration identity."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex

from playbooks.data.files import control


def validate(request):
    if (not isinstance(request, dict) or set(request) != {'service', 'sql', 'sha256'} or
            not isinstance(request['service'], str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,30}', request['service']) or
            not isinstance(request['sql'], str) or not 0 < len(request['sql'].encode()) <= 65536 or
            '\\' in request['sql'] or '\x00' in request['sql'] or
            hashlib.sha256(request['sql'].encode()).hexdigest() != request['sha256']):
        raise ValueError('Schema changes require bounded reviewed SQL, its exact hash and one service')
    return request


def apply(request):
    validate(request)
    with control.locked():
        rows = [row for row in control.settings().get('serviceRequests', []) if row['service'] == request['service']]
        if len(rows) != 1 or 'database' not in rows[0]:
            raise ValueError('Schema changes require the current approved service database')
        database = rows[0]['database']
        for key in ('name', 'applicationRole', 'migrationRole'):
            control.identity(database[key])
        if database['applicationRole'] == database['migrationRole']:
            raise ValueError('Migration and application identities must remain separate')
        credential = control.secret(request['service'] + '-migration')
        if (set(credential) != {'username', 'password'} or credential['username'] != database['migrationRole'] or
                not credential['password'] or any(c in credential['password'] for c in '\n\r\x00')):
            raise ValueError('Migration credential differs from its approved data scope')
        script = ('IFS= read -r PGPASSWORD; export PGPASSWORD; '
                  'export PGSSLMODE=verify-full PGSSLROOTCERT=/controller/certificates/server-ca.crt; '
                  'exec psql -X --no-password --single-transaction --set=ON_ERROR_STOP=1 '
                  '--host=cloudlab-postgres-rw.cloudlab-data.svc.cluster.local --username="$1" --dbname="$2"')
        control.postgres(['sh', '-ec', script, 'schema', database['migrationRole'], database['name']],
                         input=(credential['password'] + '\n' + request['sql']).encode())
    return {'service': request['service'], 'schema_sha256': request['sha256'], 'applied': True}


def main():
    from dotenv import dotenv_values
    from playbooks.access.files.preflight import ssh
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service', required=True)
    parser.add_argument('--sql-file', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    arguments = parser.parse_args()
    if arguments.sql_file.is_symlink() or arguments.sql_file.stat().st_size > 65536:
        raise ValueError('Schema input must be a bounded regular SQL file')
    request = validate({'service': arguments.service, 'sql': arguments.sql_file.read_text(encoding='utf-8'),
                        'sha256': arguments.sha256})
    values = dotenv_values(control.ROOT / '.env', interpolate=False)
    os.environ.update({key: values[key] for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD')})
    os.environ['VM_PORT'] = values.get('VM_PORT') or '22'
    source = Path(__file__).read_text().split("\nif __name__ == '__main__':")[0]
    program = "import sys; sys.path.insert(0, '/opt/cloudlab');\n" + source + '\nprint(json.dumps(apply(json.load(sys.stdin))))'
    print(ssh('VM', values['VM_HOST'], 'sudo python3 -c ' + shlex.quote(program),
              input=json.dumps(request), timeout=360))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Scoped schema operation failed; application credentials and data retained') from None
