"""Data owner validates service requests and resolves only scoped vault identities."""
import re

from automation.data.control import identity


def request(service, data, approved):
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,30}', service) or set(data) - {'database', 'bucket'}:
        raise ValueError('Invalid service data request')
    result = {'service': service, 'namespace': 'cloudlab-app-' + service}
    for kind, value in data.items():
        scope = approved.get(value.get('credentialReference'), {}) if isinstance(value, dict) else {}
        required_fields = {'kind', 'service', 'name', 'item'} | ({'migrationItem'} if kind == 'database' else set())
        if (not isinstance(value, dict) or set(value) != {'name', 'credentialReference', 'retention'} or
                value['retention'] != 'retain' or value['credentialReference'] not in approved or
                set(scope) != required_fields or
                approved[value['credentialReference']].get('kind') != kind or
                approved[value['credentialReference']].get('service') != service or
                approved[value['credentialReference']].get('name') != value['name']):
            raise ValueError('Data request requires its exact administrator-approved scope')
        for field in ('item', 'migrationItem') if kind == 'database' else ('item',):
            if not isinstance(scope[field], str) or not re.fullmatch(
                    ('cnpg' if kind == 'database' else 's3') + r'-[a-z0-9-]+-' + ('migration' if field == 'migrationItem' else 'production'), scope[field]):
                raise ValueError('Service request cannot use privileged data credentials')
        if kind == 'database':
            identity(value['name'])
        elif not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', value['name']):
            raise ValueError('Invalid service bucket name')
        result[kind] = dict(value, item=approved[value['credentialReference']]['item'])
        if kind == 'database':
            result[kind]['migrationItem'] = approved[value['credentialReference']]['migrationItem']
    return result


def resolve(requests, lookup):
    result = []
    databases, roles, buckets, services = set(), set(), set(), set()
    for requested in requests:
        if requested['service'] in services:
            raise ValueError('Duplicate service data request')
        services.add(requested['service'])
        row = {'service': requested['service'], 'namespace': requested['namespace']}
        if 'database' in requested:
            value = requested['database']
            app = lookup(value['item'], ('username', 'database'))
            migration = lookup(value['migrationItem'], ('username', 'database'))
            if app['database'] != value['name'] or migration['database'] != value['name']:
                raise ValueError('Service database differs from its scoped vault contract')
            for name in (app['username'], migration['username'], value['name']): identity(name)
            if value['name'] in databases or len({app['username'], migration['username']}) != 2 or roles & {app['username'], migration['username']}:
                raise ValueError('Service database or role scope overlaps')
            databases.add(value['name'])
            roles.update((app['username'], migration['username']))
            row['database'] = {'name': value['name'], 'applicationRole': app['username'],
                               'migrationRole': migration['username'], 'applicationItem': value['item'],
                               'migrationItem': value['migrationItem']}
        if 'bucket' in requested:
            value = requested['bucket']
            bucket = lookup(value['item'], ('BUCKET',))['BUCKET']
            if bucket != value['name'] or bucket in buckets:
                raise ValueError('Service bucket differs from its scoped vault contract or overlaps')
            buckets.add(bucket)
            row['bucket'] = {'name': bucket, 'item': value['item']}
        result.append(row)
    return result


def reconcile(values, sql, grant, admin):
    changed = False
    for row in values.get('serviceRequests', []):
        if 'database' in row:
            database = row['database']
            desired = dict(values, database=database['name'], applicationRole=database['applicationRole'],
                           migrationRole=database['migrationRole'])
            changed = grant(desired) or changed
        if 'bucket' in row:
            changed = admin.ensure_bucket(row['bucket']['name']) or changed
    return changed
