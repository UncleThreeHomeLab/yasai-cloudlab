"""Remove only stopped tailscaled's chains before selecting its iptables backend."""
import json
import subprocess

OWNED = {('filter', 'ts-input'), ('filter', 'ts-forward'), ('nat', 'ts-postrouting')}


def transaction(document):
    entries = document['nftables']
    owned = {(c['family'], c['table'], c['name']) for item in entries
             if (c := item.get('chain')) and c['family'] in ('ip', 'ip6') and
             (c['table'], c['name']) in OWNED}
    commands = []
    for item in entries:
        rule = item.get('rule')
        if not rule or (rule['family'], rule['table'], rule['chain']) in owned:
            continue
        targets = [expression[verb]['target'] for expression in rule['expr']
                   for verb in ('jump', 'goto') if verb in expression]
        if any((rule['family'], rule['table'], target) in owned for target in targets):
            if (rule['table'], rule['chain']) not in {('filter', 'INPUT'), ('filter', 'FORWARD'), ('nat', 'POSTROUTING')}:
                raise RuntimeError('Unexpected reference to a Tailscale-owned chain; cleanup refused')
            commands.append({'delete': {'rule': {key: rule[key] for key in ('family', 'table', 'chain', 'handle')}}})
    for verb in ('flush', 'delete'):
        for family, table, name in sorted(owned):
            commands.append({verb: {'chain': {'family': family, 'table': table, 'name': name}}})
    return {'nftables': commands}


def command(args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Tailscale firewall preparation failed; existing host firewall retained')
    return result.stdout


def main():
    # ExecStartPre runs after the previous daemon exits. Refuse a separate live invocation.
    running = subprocess.run(['pgrep', '-x', 'tailscaled'], capture_output=True, timeout=10)
    if running.returncode != 1:
        raise RuntimeError('Tailscale firewall preparation requires a stopped daemon')
    changes = transaction(json.loads(command(['nft', '-j', 'list', 'ruleset'])))
    if changes['nftables']:
        data = json.dumps(changes)
        command(['nft', '-j', '-c', '-f', '-'], data)
        command(['nft', '-j', '-f', '-'], data)
    # kube-router must be able to read this shared table to enforce NetworkPolicy.
    command(['/usr/sbin/iptables-save', '-t', 'filter'])
    print(json.dumps({'tailscale_firewall_prepared': True, 'scoped_commands': len(changes['nftables'])}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else 'Tailscale firewall preparation failed') from None
