"""Bind public pins to existing private identity and network interfaces."""
import json
import os
from pathlib import Path
import shlex

from automation.gitops.render import committed_payload
from automation.connectivity.preflight import ssh
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


if __name__ == '__main__':
    try: print(json.dumps(payload()))
    except Exception:
        raise SystemExit('Telemetry inputs unavailable; private values withheld') from None
