"""Fail-closed scope and preservation rules for native Harbor plans."""
import json
from pathlib import Path
import re

POLICY = json.loads((Path(__file__).resolve().parents[2] / 'infra/harbor/contract.json').read_text())
IDENTITIES = {
    'project': r'/projects/[1-9][0-9]*', 'group': r'/usergroups/[1-9][0-9]*',
    'project_member_group': r'/projects/[1-9][0-9]*/members/[1-9][0-9]*',
    'robot_account': r'/robots/[1-9][0-9]*', 'retention_policy': r'/retentions/[1-9][0-9]*',
    'immutable_tag_rule': r'/projects/[1-9][0-9]*/immutabletagrules/[1-9][0-9]*'}


def resources():
    groups = {member['group'] for member in POLICY['memberships'].values()}
    result = {}
    for kind, label, keys in (
        ('project', 'project', POLICY['projects']), ('group', 'group', groups),
        ('project_member_group', 'member', POLICY['memberships']),
        ('robot_account', 'robot', (project + '-' + role for project in POLICY['projects'] for role in ('push', 'pull'))),
        ('retention_policy', 'retention', POLICY['projects']), ('immutable_tag_rule', 'release', POLICY['projects'])):
        result.update({'harbor_' + kind + '.' + label + '[' + json.dumps(key) + ']': (kind, key) for key in keys})
    return result


def matches(values, expected):
    return all(type(values.get(key)) is type(value) and values[key] == value for key, value in expected.items())


def fields(kind, key, values):
    if kind == 'project':
        valid = matches(values, {'name': key, 'public': False, 'storage_quota': POLICY['projects'][key],
            'force_destroy': False, 'vulnerability_scanning': False, 'enable_content_trust': False,
            'enable_content_trust_cosign': False, 'auto_sbom_generation': False})
        valid = valid and values.get('registry_id') in (None, 0) and not values.get('cve_allowlist') and not values.get('deployment_security')
    elif kind == 'group':
        valid = matches(values, {'group_name': key, 'group_type': 3}) and not values.get('ldap_group_dn')
    elif kind == 'project_member_group':
        member = POLICY['memberships'][key]
        valid = matches(values, {'type': 'oidc', 'group_name': member['group'], 'role': member['role']})
    elif kind == 'robot_account':
        project, role = key.rsplit('-', 1)
        valid = matches(values, {'name': role, 'description': f'Scoped {role} for {project}', 'level': 'project',
                                  'duration': -1, 'secret_wo_version': 1}) and not values.get('disable')
        permissions = values.get('permissions') or []
        allowed = {'pull', 'push'} if role == 'push' else {'pull'}
        valid = valid and len(permissions) == 1 and matches(permissions[0], {'kind': 'project', 'namespace': project})
        if valid:
            access = permissions[0].get('access') or []
            valid = (len(access) == len(allowed) and {row.get('action') for row in access} == allowed and
                     all(matches(row, {'resource': 'repository', 'effect': 'allow'}) for row in access))
        valid = valid and not values.get('secret') and not values.get('secret_wo')
    elif kind == 'retention_policy':
        rules = values.get('rule') or []
        valid = (not values.get('schedule') and len(rules) == 1 and
                 matches(rules[0], {'always_retain': True, 'untagged_artifacts': True,
                                   'repo_matching': '**', 'tag_matching': '**', 'disabled': False}) and
                 not any(rules[0].get(field) for field in ('repo_excluding', 'tag_excluding', 'most_recently_pushed',
                     'most_recently_pulled', 'n_days_since_last_pull', 'n_days_since_last_push')))
    elif kind == 'immutable_tag_rule':
        valid = matches(values, {'repo_matching': '**', 'tag_matching': POLICY['protected_tags'], 'disabled': False})
        valid = valid and not values.get('repo_excluding') and not values.get('tag_excluding')
    else:
        valid = False
    if not valid:
        raise ValueError('Native Harbor fields exceed accepted scope or artifact-preservation policy')


def plan(document, bootstrap=False, imported=False, recovery=False):
    expected = resources()
    rows = [row for row in document.get('resource_changes', []) if row.get('mode') == 'managed']
    if {row['address'] for row in rows} != set(expected) or len(rows) != len(expected):
        raise ValueError('Native Harbor plan differs from the complete designated resource scope')
    changes = 0
    allowed_actions = (['create'], ['update'], ['no-op']) if bootstrap and recovery else (
        (['create'], ['no-op']) if bootstrap else (['update'], ['no-op']))
    for row in rows:
        kind, key = expected[row['address']]
        change, after = row['change'], row['change'].get('after') or {}
        if row.get('previous_address') or change.get('importing'):
            raise ValueError('Harbor imports and address changes require explicit custody maintenance')
        actions = change['actions']
        if actions not in allowed_actions:
            raise ValueError('Harbor lifecycle operation is outside its reviewed ownership mode')
        if kind == 'project' and any((change.get('before') or {}).get(name) for name in ('cve_allowlist', 'deployment_security')):
            raise ValueError('Retained project security fields require explicit review before any API change')
        if kind == 'robot_account' and actions == ['update']:
            before = change.get('before') or {}
            unchanged = {k: v for k, v in before.items() if k != 'secret_wo_version'} == {
                k: v for k, v in after.items() if k != 'secret_wo_version'}
            if not imported or before.get('secret_wo_version') not in (None, 0) or not unchanged:
                raise ValueError('Routine project and retention apply must not rotate or change robots')
        fields(kind, key, after)
        changes += actions != ['no-op']
    if not bootstrap:
        inventory({'values': {'root_module': {'resources': [
            {'address': row['address'], 'mode': 'managed', 'values': row['change']['after']} for row in rows]}}})
    return changes


def inventory(document):
    expected, result = resources(), {}
    rows = document.get('values', {}).get('root_module', {}).get('resources', [])
    if {row['address'] for row in rows if row.get('mode') == 'managed'} != set(expected):
        raise ValueError('Native Harbor state does not contain the complete designated resource scope')
    values = {row['address']: row['values'] for row in rows if row.get('mode') == 'managed'}
    for address, (kind, key) in expected.items():
        attributes = values[address]
        fields(kind, key, attributes)
        if not re.fullmatch(IDENTITIES[kind], attributes.get('id') or ''):
            raise ValueError('Native Harbor resource identity is missing or outside its resource type')
        result[address] = attributes['id']
        if kind in ('project_member_group', 'retention_policy', 'immutable_tag_rule'):
            project = POLICY['memberships'][key]['project'] if kind == 'project_member_group' else key
            project_id = values['harbor_project.project[' + json.dumps(project) + ']']['id']
            if attributes['scope' if kind == 'retention_policy' else 'project_id'] != project_id:
                raise ValueError('Native Harbor resource escaped its designated project')
        if kind == 'project_member_group':
            group_id = values['harbor_group.group[' + json.dumps(POLICY['memberships'][key]['group']) + ']']['id']
            if attributes['group_id'] != int(group_id.rsplit('/', 1)[1]):
                raise ValueError('Harbor project role refers to another OIDC group')
    if len(set(result.values())) != len(result):
        raise ValueError('Harbor state maps multiple resources to the same identity')
    return result
