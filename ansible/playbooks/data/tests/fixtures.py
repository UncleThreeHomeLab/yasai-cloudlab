"""Disposable native CA execution with only external API and write boundaries replaced."""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import yaml

COMPONENT = Path(__file__).resolve().parents[1]
OWNER = 'cloudlab-data-bootstrap'
PUBLIC = '-----BEGIN CERTIFICATE-----\npublic fixture'


def retained():
    return {
        'fixture_application': {'metadata': {'labels': {'cloudlab.io/owner': OWNER}},
            'spec': {'source': {'helm': {'valuesObject': {
                'maintenance': False, 'serviceConsumers': ['cloudlab-app-notes'],
                'database': 'notes', 'applicationRole': 'notes_app', 'migrationRole': 'notes_migration',
                'backupRole': 'backup'}}}}},
        'fixture_cluster': {'metadata': {'uid': 'retained-cluster'}, 'spec': {'instances': 1},
            'status': {'conditions': [{'type': 'Ready', 'status': 'True'}], 'currentPrimary': 'cloudlab-postgres-1'}},
        'fixture_sql_before': 'catalog-before', 'fixture_sql_after': 'catalog-before',
        'fixture_secret': {'metadata': {'ownerReferences': [{'uid': 'retained-cluster'}]},
            'data': {'ca.crt': base64.b64encode(PUBLIC.encode()).decode(), 'ca.key': 'never-project'}},
        'fixture_namespace': {'metadata': {'labels': {'cloudlab.io/owner': 'service-platform'},
            'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-services:/Namespace:/approved'}}},
        'fixture_current': {'metadata': {'uid': 'retained-target', 'resourceVersion': '7',
            'labels': {'cloudlab.io/owner': OWNER, 'retained-label': 'keep'},
            'annotations': {'retained-annotation': 'keep'}}, 'data': {'ca.crt': PUBLIC}},
        'fixture_prior': {'spec': {'source': {'targetRevision': 'a'*40,
            'helm': {'valuesObject': {'definition': {'name': 'notes'}}}}},
            'status': {'sync': {'revision': 'a'*40, 'status': 'Synced'}, 'health': {'status': 'Healthy'},
                'operationState': {'phase': 'Succeeded', 'syncResult': {'revision': 'b'*40}}}}}


def run_native(values, entry='native-ca.yml'):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'tasks').mkdir()
        (root / 'templates').mkdir()
        (root / 'files').mkdir()
        (root / 'contract.json').write_bytes((COMPONENT.parents[2] / 'platform/data/contract.json').read_bytes())
        for path in (COMPONENT / 'templates').glob('*.j2'):
            (root / 'templates' / path.name).write_text(path.read_text())
        (root / 'files/privilege-catalog.sql').write_bytes((COMPONENT / 'files/privilege-catalog.sql').read_bytes())
        inputs = root / 'inputs.json'
        inputs.write_text(json.dumps(dict(values, fixture_directory=directory)))
        registers = {'data_ca_application': 'fixture_application', 'data_ca_cluster': 'fixture_cluster',
            'data_ca_secret': 'fixture_secret', 'data_ca_namespace_info': 'fixture_namespace', 'data_sql_cluster': 'fixture_cluster',
            'data_ca_current_info': 'fixture_current', 'data_ca_prior_application': 'fixture_prior'}
        paths = [*(COMPONENT / 'tasks').glob('ca-*.yml'), *(COMPONENT / 'tasks').glob('sql-*.yml'),
                 COMPONENT / 'tasks/native-settings.yml']
        for path in paths:
            tasks = copy.deepcopy(yaml.safe_load(path.read_text()))
            for task in tasks:
                if 'kubernetes.core.k8s_info' in task:
                    task.pop('kubernetes.core.k8s_info')
                    register = task.pop('register')
                    value = registers[register]
                    task['ansible.builtin.set_fact'] = {register:
                        {'resources': '{{ [' + value + '] if ' + value + ' else [] }}'}}
                elif 'kubernetes.core.k8s_json_patch' in task:
                    expression = task.pop('kubernetes.core.k8s_json_patch')['patch'][3:-3]
                    task['ansible.builtin.copy'] = {'content': '{{ (' + expression + ') | to_json }}',
                        'dest': '{{ fixture_directory }}/patch.json', 'mode': '0600'}
                elif 'ansible.builtin.command' in task:
                    if task.get('register') in ('data_sql_before', 'data_sql_after'):
                        response = 'fixture_sql_before' if task['register'] == 'data_sql_before' else 'fixture_sql_after'
                        task['ansible.builtin.command'] = {'argv': ['/bin/echo', '{{ ' + response + ' }}']}
                    else:
                        expression = task.pop('ansible.builtin.command')['stdin'][3:-3]
                        sql = path.name == 'sql-grants.yml'
                        content = '{{ (' + expression + ') }}' if sql else '{{ (' + expression + ') | from_yaml | to_json }}'
                        target = 'sql-{{ data_sql_database.name }}.sql' if sql else 'create.json'
                        task['ansible.builtin.copy'] = {'content': content,
                            'dest': '{{ fixture_directory }}/' + target, 'mode': '0600'}
            (root / 'tasks' / path.name).write_text(yaml.safe_dump(tasks, sort_keys=False))
        play = yaml.safe_load((COMPONENT / entry).read_text())
        play[0]['vars']['ansible_python_interpreter'] = sys.executable
        play[0]['vars']['fixture_inputs'] = "{{ lookup('file', lookup('env', 'DATA_CA_FIXTURE')) | from_json }}"
        play[0]['vars'].update({key: '{{ fixture_inputs.' + key + ' }}' for key in values})
        play[0]['vars']['fixture_directory'] = '{{ fixture_inputs.fixture_directory }}'
        (root / entry).write_text(yaml.safe_dump(play, sort_keys=False))
        result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(root / entry)],
            capture_output=True, text=True, timeout=90,
            env=dict(os.environ, DATA_CA_FIXTURE=str(inputs),
                     ANSIBLE_CONFIG=str(COMPONENT.parent / 'host/files/ansible.cfg')))
        outputs = {name: json.loads((root / (name + '.json')).read_text())
            for name in ('create', 'patch') if (root / (name + '.json')).exists()}
        outputs.update({path.stem: path.read_text() for path in root.glob('sql-*.sql')})
        return result, outputs
