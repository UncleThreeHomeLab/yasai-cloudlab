"""Outside-client proof of private S3 routing and absent public data listeners."""
import json
import os
from pathlib import Path
import socket
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from automation.credentials.vault import fields
from automation.connectivity.verify import remote
from automation.connectivity.traffic import https
from automation.connectivity.contract import host_rules
from automation.connectivity.dns_wire import query
from automation.data.s3 import S3


def run():
    values = fields('s3-notes-production', ('ENDPOINT', 'BUCKET', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY', 'REGION'))
    hostname = urlsplit(values['ENDPOINT']).hostname
    runtime = remote('runtime')
    expected = runtime['private']['tailnet_gateway']
    if socket.gethostbyname(hostname) != expected or query('1.1.1.1', hostname)['addresses']:
        raise RuntimeError('S3 DNS is not private to the selected tailnet gateway')
    client = S3(values['ENDPOINT'], values['ACCESS_KEY_ID'], values['SECRET_ACCESS_KEY'], values['REGION'])
    client.request('HEAD', values['BUCKET'])
    list(client.objects(values['BUCKET']))
    public = next(rule['hostname'] for rule in host_rules(json.loads(os.environ['CLOUDFLARE_ACCESS_HOSTS']), runtime['zone']) if rule['access'] == 'public')
    response = https(public, headers={'Host': hostname}, path='/' + values['BUCKET'] + '/')
    if not response['public_peer'] or not response['headers'].get('cf-ray') or response['status'] not in (403, 404, 530):
        raise RuntimeError('Outside Cloudflare caller was not denied access to S3')
    for prefix in ('VM', 'VM2'):
        for port in (5432, 8333, 8334):
            try:
                connection = socket.create_connection((os.environ[prefix + '_HOST'], port), timeout=3)
            except (ConnectionRefusedError, TimeoutError):
                continue
            connection.close()
            raise RuntimeError('A public database or object port is reachable')
    return {'outside_allowed_tailnet_s3': True, 'public_s3_denied': True,
            'public_sql_s3_ports_closed': True, 'private_dns': True,
            's3_network': client.counters(), 'b2_requests': 0}


if __name__ == '__main__':
    try:
        print(json.dumps(run()))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else 'External data isolation proof failed; diagnostics withheld') from None
