"""Remove stopped K3s rules without round-tripping or flushing host firewalls."""
import json
import re


def cleanup_transaction(document):
    entries = document['nftables']
    owned = set()
    for entry in entries:
        chain = entry.get('chain', {})
        if (chain.get('family') in ('ip', 'ip6') and
                chain.get('table') in ('filter', 'nat', 'mangle', 'raw') and
                re.fullmatch(r'(?:KUBE-|CNI-|FLANNEL-)[A-Za-z0-9_-]+', chain.get('name', ''))):
            owned.add((chain['family'], chain['table'], chain['name']))
    commands = []
    for entry in entries:
        rule = entry.get('rule')
        if not rule:
            continue
        key = (rule['family'], rule['table'], rule['chain'])
        if key in owned:
            continue
        targets = [expr[verb]['target'] for expr in rule['expr']
                   for verb in ('jump', 'goto') if verb in expr]
        if any((key[0], key[1], target) in owned for target in targets):
            if key[0] not in ('ip', 'ip6') or key[1] not in ('filter', 'nat', 'mangle', 'raw'):
                raise RuntimeError('Unexpected external reference to Kubernetes chains')
            commands.append({'delete': {'rule': {k: rule[k] for k in ('family', 'table', 'chain', 'handle')}}})
    # Flush all owned chains before deleting any, so inter-chain references vanish.
    for verb in ('flush', 'delete'):
        for family, table, name in sorted(owned):
            commands.append({verb: {'chain': {'family': family, 'table': table, 'name': name}}})
    return {'nftables': commands}


def cleanup(command):
    document = json.loads(command(['nft', '-j', 'list', 'ruleset']).stdout)
    transaction = cleanup_transaction(document)
    if transaction['nftables']:
        payload = json.dumps(transaction)
        command(['nft', '-j', '-c', '-f', '-'], input=payload)
        command(['nft', '-j', '-f', '-'], input=payload)
