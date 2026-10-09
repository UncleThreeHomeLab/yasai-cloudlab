"""Identity state in the shared physical CNPG generation; no realm export backup."""
import hashlib
import json
import time

from automation.data import control
from automation.identity.maintenance import APP, OWNER
from automation.identity.configuration import compile_state, REALMS
from automation.mesh.kube import get


def signature_state(sql, database):
    # Key material stays in the physical database. Only hashes enter the receipt.
    statement = """SELECT coalesce(json_agg(t ORDER BY t.component_id,t.name,t.hash),'[]'::json)
      FROM (SELECT cc.component_id,cc.name,encode(sha256(convert_to(cc.value,'UTF8')),'hex') hash
      FROM component_config cc JOIN component c ON c.id=cc.component_id
      WHERE c.provider_type='org.keycloak.keys.KeyProvider') t"""
    rows = json.loads(sql(statement, database))
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def capture_state():
    app = get('application.argoproj.io', APP, 'argocd')
    if not app:
        return None
    if app['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER:
        raise RuntimeError('Identity recovery cannot inventory a foreign owner')
    values = app['spec']['source']['helm']['valuesObject']
    if not values.get('enabled'):
        return None
    database, role = values['database'], values['databaseRole']
    control.identity(database)
    control.identity(role)
    if int(control.sql('SELECT pg_database_size(current_database())', database)) > 1073741824:
        raise RuntimeError('Identity database exceeds the shared monthly generation budget')
    return {'database': database, 'role': role, 'captured_at': time.time(),
            'signing_state_sha256': signature_state(control.sql, database),
            'users': int(control.sql('SELECT count(*) FROM user_entity', database)),
            'disabled_users': int(control.sql('SELECT count(*) FROM user_entity WHERE enabled=false', database)),
            'recovery_inputs': 'Current vault credentials and private membership/revocation source required; no issuer reopening'}


def verify_restored(manifest, sql):
    identity = manifest.get('identity')
    if identity is None:
        return {'identity_state_present': False}
    database = identity['database']
    control.identity(database)
    control.identity(identity['role'])
    if signature_state(sql, database) != identity['signing_state_sha256']:
        raise RuntimeError('Restored identity signing state differs from the physical generation')
    if (int(sql('SELECT count(*) FROM user_entity', database)) != identity['users'] or
            int(sql('SELECT count(*) FROM user_entity WHERE enabled=false', database)) != identity['disabled_users']):
        raise RuntimeError('Restored identity inventory differs')
    # No restored Keycloak server, route or issuer is opened by this SQL-only proof.
    # Session tables are cleared before any future controlled server can start.
    tables = json.loads(sql("SELECT coalesce(json_agg(table_name),'[]'::json) FROM information_schema.tables "
                            "WHERE table_schema='public' AND table_name IN "
                            "('offline_user_session','offline_client_session','user_session','client_session')", database))
    if tables:
        sql('TRUNCATE ' + ','.join(control.identity(name) for name in tables) + ' CASCADE;', database)
    return {'identity_state_present': True, 'identity_signing_state_preserved': True,
            'restored_sessions_invalidated': True, 'restored_identity_issuer_exposed': False,
            'identity_data_age_seconds': round(max(0, time.time() - identity['captured_at']), 3),
            'membership_revocation_review_required_before_reopening': True}


def restore_configuration(realm, rp_id, source, credentials, revocations, existing_clients):
    """Compile current inputs against a mandatory isolated inventory before reopening.

    Normal reconciliation must not recreate removed clients. An old physical
    generation may still contain them, so restore disables only those that exist.
    Human credential changes and stale memberships still require recovery review.
    """
    if realm not in REALMS:
        raise ValueError('Restore requires a managed realm')
    if (not isinstance(existing_clients, list) or
            any(not isinstance(row, dict) or not isinstance(row.get('clientId'), str)
                or not row['clientId'] for row in existing_clients)):
        raise ValueError('Complete restored client inventory is required')
    identifiers = [row['clientId'] for row in existing_clients]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError('Restored client inventory is ambiguous')
    # Both realms must validate before any restore import can be written.
    states = {name: compile_state(name, rp_id, source, credentials, revocations) for name in REALMS}
    state = states[realm]
    for identifier in revocations['realms'].get(realm, {}).get('removed_clients', []):
        if identifier in identifiers:
            state['clients'].append({'clientId': identifier, 'enabled': False})
    return state
