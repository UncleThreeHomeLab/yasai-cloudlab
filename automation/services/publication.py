"""Publish explicit intent through the versioned private catalog and existing DNS owner."""
import json

from dotenv import dotenv_values

from automation.services.contract import ROOT
from automation.services.inputs import catalog


def set_intent(definition, publication):
    if publication not in ('ready', 'published', 'retired'):
        raise ValueError('Unsupported publication intent')
    value = catalog(required=True)
    import copy
    previous = copy.deepcopy(value)
    matches = [row for row in value['catalog'] if row['definition'] == definition]
    if len(matches) != 1: raise ValueError('Publication requires one exact administrator catalog entry')
    matches[0]['publication'] = publication
    from automation.services.source import publish
    publish(value, expected=previous)


def private_dns(definition, *, published):
    from playbooks.access.files.preflight import ssh
    from playbooks.access.files.contract import private_names
    import os
    import shlex
    values = dotenv_values(ROOT / '.env', interpolate=False)
    baseline = private_names(json.loads(values.get('PRIVATE_ACCESS_HOSTS') or '[]'))
    helper = (ROOT / 'ansible/playbooks/access/files/service_dns.py').read_text()
    # The existing DNS owner serializes and validates its complete generation.
    code = "import sys;sys.path.insert(0,'/var/lib/cloudlab/private-dns');\n" + helper
    code += "\nimport json,fcntl\nfrom pathlib import Path\nsys.path.insert(0,'/var/lib/cloudlab/private-dns')\nimport dns_host\n"
    code += "request=json.load(sys.stdin)\nwith (dns_host.STATE/'lock').open('a') as lock:\n fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)\n payload=json.loads((dns_host.STATE/'inputs.json').read_text())\n result=dns_host.configure(desired(payload,request['exposure'],request['baseline'],published=request['published']))\nprint(json.dumps({'dns_ready':result['dns_ready']}))\n"
    for prefix in ('VM', 'VM2'):
        for key in ('HOST', 'USER', 'PASSWORD'):
            if not values.get(prefix + '_' + key): raise ValueError('Private publication requires both existing VM inputs')
            os.environ[prefix + '_' + key] = values[prefix + '_' + key]
        os.environ[prefix + '_PORT'] = values.get(prefix + '_PORT') or '22'
        result = json.loads(ssh(prefix, os.environ[prefix + '_HOST'], 'python3 -c ' + shlex.quote(code),
            input=json.dumps({'exposure': definition['exposure'], 'baseline': baseline, 'published': published}), timeout=120))
        if result != {'dns_ready': True}: raise RuntimeError('Private service DNS did not converge on both nodes')
