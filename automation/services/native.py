"""Execute scoped service stages through the accepted native root and its lock."""
import copy
import fcntl
import json
from pathlib import Path

from playbooks.infrastructure.files import command
from playbooks.infrastructure.files.native import require
from automation.services.external import declarations, guarded_plan


def observed_exposure(state, key, definition, desired):
    """Native state makes an interrupted apply resumable without another journal."""
    previous = copy.deepcopy(desired)
    selected = None
    published = False
    for resource in state.get('resources', []):
        if resource.get('mode') != 'managed': continue
        for instance in resource.get('instances', []):
            value = instance['attributes']
            if resource['type'] == 'cloudflare_dns_record' and resource['name'] == 'service_publication' and instance.get('index_key') == key:
                if value['name'] != definition['exposure']['hostname']:
                    raise ValueError('Existing service DNS belongs to a different exposure')
                published = True
            if resource['type'] == 'cloudflare_zero_trust_tunnel_cloudflared_config' and resource['name'] == 'routing':
                rows = [row for row in value['config']['ingress'] if row.get('hostname') == definition['exposure']['hostname']]
                if len(rows) > 1: raise ValueError('Ambiguous service tunnel routing')
                if rows: selected = rows[0]
    if key in previous.get('service_exposures', {}):
        entry = previous['service_exposures'][key]
        if selected and (selected['service'] != entry['origin'] or selected['origin_request'].get('no_tls_verify') is not False):
            raise ValueError('Existing service tunnel differs from its approved origin')
        entry.update(routed=selected is not None, published=published)
    elif selected or published:
        raise ValueError('Native service exists without reviewed exposure input; retain access protection and inspect private state')
    return previous


def stage(definition, operation, origin, application=None):
    """Read-only credential mounts are replaced only by the explicit services entry point."""
    command.WORK.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (command.WORK / 'cloudflare.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        client = command.Client('cloudflare')
        if (client.path / 'errored.tfstate').exists():
            raise RuntimeError('Recover the existing encrypted native state before service publication')
        client.initialize()
        state = json.loads(require(client.native('state', 'pull')).stdout)
        key = 'service_' + definition['name'].replace('-', '_')
        desired = observed_exposure(state, key, definition, client.desired)
        desired = declarations(definition, desired, operation=operation, origin=origin, application=application)
        # Persist complete intent before applying. Its single atomic input is the
        # same source used by ordinary drift checks; native state keeps identities.
        destination = command.PRIVATE / 'cloudflare/desired.tfvars.json'
        if desired != client.desired:
            client.unchanged_inputs()
            temporary = destination.with_suffix('.service.tmp')
            if temporary.exists() and json.loads(temporary.read_text()) != desired:
                raise RuntimeError('Previous private intent differs; inspect it before another operation')
            if not temporary.exists():
                with temporary.open('x') as output:
                    temporary.chmod(0o600)
                    json.dump(desired, output, sort_keys=True)
            temporary.replace(destination)
            client = command.Client('cloudflare')
        filename = 'service-' + operation + '.tfplan'
        require(client.native('plan', '-input=false', '-lock-timeout=0s',
                              '-var-file=desired.tfvars.json', '-out=' + filename), (0, 2))
        document = json.loads(require(client.native('show', '-json', filename)).stdout)
        guarded_plan(document, definition, operation)
        if command.shared_identities(document) != client.inventory:
            raise ValueError('Shared infrastructure identities changed; service operation refused')
        client.unchanged_inputs()
        require(client.native('apply', '-input=false', '-lock-timeout=0s', filename))
        client.unchanged_inputs()
        return desired
