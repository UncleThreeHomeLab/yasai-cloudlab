"""Read-only discovery and behavioral expectations; never generate deployment resources."""
import json
import os
from pathlib import Path
import shlex
import sys

from playbooks.access.files.preflight import ssh

ROOT = Path(__file__).resolve().parents[4]


def metadata():
    # Inspection uses the versioned module through stdin, without configuring the VM.
    script = (ROOT / 'ansible/playbooks/observability/files/discovery.py').read_text()
    script = "import sys,json;sys.path.insert(0,'/opt/cloudlab');\n" + script + '\nprint(json.dumps(run()))'
    return json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 -c ' + shlex.quote(script), timeout=60))


def verification_payload(inputs):
    from playbooks.observability.files.configuration import POLICY
    from playbooks.observability.files.chart import render
    from playbooks.observability.files.slo import rules
    from playbooks.services.files.inputs import catalog
    source, discovered = inputs['source'], inputs['metadata']
    entries = [entry for entry in catalog(required=True)['catalog'] if entry['publication'] == 'published' and
               entry['definition']['name'] == 'notes' and entry['approval'].get('chartPath') == 'apps/notes']
    if len(entries) != 1 or entries[0]['definition']['exposure']['class'] != 'public':
        raise ValueError('Telemetry proof requires its approved public Notes service')
    configurations = {component: {obj['metadata']['name']: obj['data'] for obj in render(component)
                                  if obj['kind'] == 'ConfigMap'} for component in ('loki', 'tempo')}
    dashboards = {path.name: json.loads(path.read_text())
                  for path in sorted((ROOT / 'platform/observability/prometheus/dashboards').glob('*.json'))}
    configurations['prometheus'] = {'cloudlab-dashboards': {
        path.name: path.read_text() for path in sorted((ROOT / 'platform/observability/prometheus/dashboards').glob('*.json'))}}
    configurations['kiali'] = {obj['metadata']['name']: obj['data']
        for obj in render('kiali', inputs['kiali_values']) if obj['kind'] == 'ConfigMap'}
    ports = {obj['metadata']['name']: obj['spec']['ports'] for component in ('alloy', 'tempo')
             for obj in render(component) if obj['kind'] == 'Service'}
    return {'repository': source['repository'], 'revision': source['revision'], 'policy': POLICY,
            'images': json.loads((ROOT / 'platform/observability/images.lock.json').read_text()),
            'collector': (ROOT / 'platform/observability/config.alloy').read_text(),
            'backend_configurations': configurations, 'service_ports': ports, 'slo': rules(), 'dashboards': dashboards,
            'notes_origin': 'https://' + entries[0]['definition']['exposure']['hostname'],
            'grafana_origin': 'https://' + discovered['grafanaHost'],
            'kiali_origin': 'https://' + discovered['kialiHost']}


if __name__ == '__main__':
    try:
        if len(sys.argv) != 1:
            raise ValueError('Verification inputs must arrive through stdin')
        print(json.dumps(verification_payload(json.load(sys.stdin))))
    except Exception:
        raise SystemExit('Telemetry inputs unavailable; private values withheld') from None
