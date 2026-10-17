"""Bind public pins to existing private identity and network interfaces."""
import json
import os
from pathlib import Path
import shlex
import sys

from playbooks.argocd.files.render import committed_payload
from playbooks.access.files.preflight import ssh
from automation.observability.configuration import grafana
from automation.observability.values import values

ROOT = Path(__file__).resolve().parents[2]


def metadata():
    # Inspection uses the versioned module through stdin, without configuring the VM.
    script = (ROOT / 'automation/observability/discovery.py').read_text()
    script = "import sys,json;sys.path.insert(0,'/opt/cloudlab');\n" + script + '\nprint(json.dumps(run()))'
    return json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 -c ' + shlex.quote(script), timeout=60))


def payload():
    source = committed_payload()
    discovered = metadata()
    return compile_payload(source, discovered)


def compile_payload(source, metadata):
    host_aliases = [{'ip': metadata['gatewayIP'], 'hostnames': [metadata['loginHost']]}]
    components = {name: {} for name in ('prometheus', 'loki', 'tempo', 'alloy', 'kiali')}
    prometheus = values('prometheus')
    prometheus['grafana']['grafana.ini'] = grafana('https://' + metadata['loginHost'] + '/realms/platform',
                                                'https://' + metadata['grafanaHost'])['ini']
    prometheus['grafana']['hostAliases'] = host_aliases
    components['prometheus'] = {'kube-prometheus-stack': prometheus}
    kiali = values('kiali')
    kiali['auth']['openid']['issuer_uri'] = 'https://' + metadata['loginHost'] + '/realms/platform'
    kiali['deployment']['host_aliases'] = host_aliases
    kiali['external_services']['grafana']['external_url'] = 'https://' + metadata['grafanaHost']
    kiali['server'] = {'web_fqdn': metadata['kialiHost'], 'web_port': '443', 'web_schema': 'https'}
    components['kiali'] = {'kiali-server': kiali}
    configuration = {key: value for key, value in metadata.items() if key != 'gatewayIP'}
    return {'repository': source['repository'], 'revision': source['revision'],
            'configuration': dict(configuration, enabled=True), 'components': components}


def verification_payload():
    from automation.observability.configuration import POLICY
    from automation.observability.chart import render
    from automation.observability.slo import rules
    from automation.services.inputs import catalog
    source, discovered = committed_payload(), metadata()
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
        for obj in render('kiali', compile_payload(source, discovered)['components']['kiali']) if obj['kind'] == 'ConfigMap'}
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
        mode = sys.argv[1] if len(sys.argv) == 2 else 'bootstrap' if len(sys.argv) == 1 else ''
        print(json.dumps({'bootstrap': payload, 'verify': verification_payload}[mode]()))
    except Exception:
        raise SystemExit('Telemetry inputs unavailable; private values withheld') from None
