"""Prove rendered Alertmanager routing on isolated local transports and storage."""
import base64
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[4]
FIXTURE = Path('/fixture')
SECRET_NAME = 'alertmanager-notification-fixture'
SECRET = FIXTURE / 'secrets' / SECRET_NAME
MANAGER = 'http://alertmanager:9093'
WEBHOOK = 'https://incident-receiver.cloudlab-app-incident-receiver.svc:9443'


def render_config(inputs):
    import yaml
    from playbooks.observability.tests.fixtures import notification_application
    from playbooks.observability.files.chart import render
    app = notification_application(inputs)
    overrides = app['spec']['source']['helm']['valuesObject']
    secret = next(obj for obj in render('prometheus', overrides)
                  if obj['kind'] == 'Secret' and obj['metadata']['name'] == 'alertmanager-cloudlab')
    raw = base64.b64decode(secret['data']['alertmanager.yaml'], validate=True)
    yaml.safe_load(raw)
    pending = FIXTURE / 'alertmanager.yaml.pending'
    pending.write_bytes(raw)
    pending.chmod(0o644)
    pending.replace(FIXTURE / 'alertmanager.yaml')


def prepare():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from playbooks.observability.tests.fixtures import notification_inputs
    FIXTURE.mkdir(parents=True, exist_ok=True)
    SECRET.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Isolated notification fixture CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
              key_encipherment=False, data_encipherment=False, key_agreement=False,
              key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server = (x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'notification fixture')])).issuer_name(ca_name)
        .public_key(server_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('smtp.fixture.invalid'),
            x509.DNSName('incident-receiver.cloudlab-app-incident-receiver.svc')]), critical=False)
        .sign(ca_key, hashes.SHA256()))
    (SECRET / 'ca.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (FIXTURE / 'server.crt').write_bytes(server.public_bytes(serialization.Encoding.PEM))
    (FIXTURE / 'server.key').write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chown(FIXTURE / 'server.key', 65534, 65534)
    (FIXTURE / 'server.key').chmod(0o400)
    for name in ('token', 'password'):
        path = SECRET / name
        path.write_text(secrets.token_urlsafe(32))
        os.chown(path, 65534, 65534)
        path.chmod(0o400)
    (SECRET / 'ca.crt').chmod(0o444)
    os.chown(FIXTURE, 65534, 65534)
    FIXTURE.chmod(0o700)
    state = Path('/alertmanager-state')
    os.chown(state, 65534, 65534)
    state.chmod(0o700)
    inputs = notification_inputs()
    (FIXTURE / 'inputs.json').write_text(json.dumps(inputs))
    render_config(inputs)
    print(json.dumps({'native_notification_config_prepared': True, 'production_credentials': False}))


def request(url, value=None, token=True, method=None):
    headers = {'Content-Type': 'application/json'}
    context = None
    if url.startswith(WEBHOOK):
        context = ssl.create_default_context(cafile=str(SECRET / 'ca.crt'))
        if token:
            headers['Authorization'] = 'Bearer ' + ((SECRET / 'token').read_text() if token is True else token)
    req = urllib.request.Request(url, data=json.dumps(value).encode() if value is not None else None,
                                 headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=5, context=context) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise RuntimeError('Notification fixture response exceeded bound')
    return raw


def wait(check, seconds=60, label='notification delivery'):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = check()
            if result: return result
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(0.5)
    raise RuntimeError('Notification fixture did not converge: ' + label)


def events():
    return json.loads(request(WEBHOOK + '/events'))


def delivered(name, status, channels):
    rows = events()['events']
    return all(any(row['channel'] == channel and row['status'] == status and
                   (name in row.get('subject', '') if channel == 'email' else row.get('name') == name)
                   for row in rows) for channel in channels)


def alert(name, service='prices', resolved=False):
    now = datetime.now(timezone.utc)
    return {'labels': {'alertname': name, 'service': service, 'severity': 'critical'},
        'annotations': {'summary': 'Isolated notification proof'},
        'startsAt': (now - timedelta(minutes=1)).isoformat(),
        'endsAt': (now - timedelta(seconds=1) if resolved else now + timedelta(hours=1)).isoformat()}


def send_alert(value):
    request(MANAGER + '/api/v2/alerts', [value])


def verify():
    wait(lambda: request(MANAGER + '/-/ready'), label='Alertmanager readiness')
    wait(lambda: request(WEBHOOK + '/health', token=False), label='TLS receiver readiness')
    for token in (False, 'wrong-fixture-token'):
        try:
            request(WEBHOOK + '/alerts/primary', {'alerts': []}, token=token)
        except urllib.error.HTTPError as error:
            if error.code != 401: raise RuntimeError('Wrong fixture credential was not rejected') from None
        else:
            raise RuntimeError('Missing or wrong fixture credential was accepted')
    failing = alert('FixtureFanout')
    send_alert(failing)
    wait(lambda: delivered('FixtureFanout', 'firing', ['email', '/alerts/primary', '/alerts/secondary']))
    wait(lambda: all(events()['redirects'][str(code)] > 0 for code in (307, 308)),
         label='approved redirect endpoints receiving native notifications')
    time.sleep(2)
    if events()['off_path_callbacks']:
        raise RuntimeError('Native webhook followed a redirect outside its approved path')
    wait(lambda: events()['failed_requests'] > 0, label='optional receiver returning 503')
    def failure_visible():
        text = request(MANAGER + '/metrics').decode()
        return any(line.startswith('alertmanager_notifications_failed_total{') and
                   float(line.rsplit(' ', 1)[1]) > 0 for line in text.splitlines())
    wait(failure_visible)
    request(WEBHOOK + '/control', {'fail': False})
    wait(lambda: delivered('FixtureFanout', 'firing', ['/alerts/failing']))
    send_alert(alert('FixtureFanout', resolved=True))
    wait(lambda: delivered('FixtureFanout', 'resolved',
                          ['email', '/alerts/primary', '/alerts/secondary', '/alerts/failing']))
    send_alert(alert('FixtureFallback', service='unmatched'))
    wait(lambda: delivered('FixtureFallback', 'firing', ['email']))
    send_alert(alert('FixtureFallback', service='unmatched', resolved=True))
    wait(lambda: delivered('FixtureFallback', 'resolved', ['email']))
    now = datetime.now(timezone.utc)
    silence = {'matchers': [{'name': 'alertname', 'value': 'FixtureSilenced', 'isRegex': False}],
        'startsAt': (now - timedelta(seconds=1)).isoformat(),
        'endsAt': (now + timedelta(hours=1)).isoformat(),
        'createdBy': 'isolated-fixture', 'comment': 'State persistence proof'}
    identifier = json.loads(request(MANAGER + '/api/v2/silences', silence))['silenceID']
    stable = alert('FixtureDedup')
    send_alert(stable)
    wait(lambda: delivered('FixtureDedup', 'firing', ['email', '/alerts/primary', '/alerts/secondary', '/alerts/failing']))
    receipt = {'silence': identifier, 'alert': stable,
               'dedup_count': sum(row.get('name') == 'FixtureDedup' for row in events()['events'])}
    (FIXTURE / 'restart.json').write_text(json.dumps(receipt))
    print(json.dumps({'firing_and_resolved': True, 'smtp_tls_auth': True, 'webhook_tls_bearer': True,
        'missing_wrong_auth_rejected': True, 'fanout_and_fallback': True, 'failure_visible': True,
        'redirect307_and_308_confined': True}))


def verify_restart():
    wait(lambda: request(MANAGER + '/-/ready'))
    receipt = json.loads((FIXTURE / 'restart.json').read_text())
    silence = json.loads(request(MANAGER + '/api/v2/silence/' + receipt['silence']))
    if silence['status']['state'] != 'active': raise RuntimeError('Silence did not survive replacement')
    send_alert(receipt['alert'])
    send_alert(alert('FixtureSilenced'))
    time.sleep(5)
    rows = events()['events']
    if sum(row.get('name') == 'FixtureDedup' for row in rows) != receipt['dedup_count']:
        raise RuntimeError('Deduplication state did not survive replacement')
    if any(row.get('name') == 'FixtureSilenced' or 'FixtureSilenced' in row.get('subject', '') for row in rows):
        raise RuntimeError('Persisted silence did not suppress matching alert')
    print(json.dumps({'silence_persisted': True, 'deduplication_persisted': True}))


def remove_subscription():
    inputs = json.loads((FIXTURE / 'inputs.json').read_text())
    inputs['platformNotifications']['subscriptions'] = []
    render_config(inputs)


def verify_removal():
    request(MANAGER + '/-/reload', {}, method='POST')
    send_alert(alert('FixtureRemoval'))
    wait(lambda: delivered('FixtureRemoval', 'firing', ['email']))
    time.sleep(2)
    if any(row.get('name') == 'FixtureRemoval' for row in events()['events']):
        raise RuntimeError('Removed subscription still delivered to webhook')
    if events()['off_path_callbacks']:
        raise RuntimeError('Native webhook redirected outside its approved path during lifecycle checks')
    status = json.loads(request(MANAGER + '/api/v2/status'))
    import yaml
    config = yaml.safe_load(status['config']['original'])
    if {row['name'] for row in config['receivers']} != {
            'operator-email', 'primary', 'secondary', 'failing', 'redirect307', 'redirect308'}:
        raise RuntimeError('Subscription removal deleted shared receiver')
    receipt = json.loads((FIXTURE / 'restart.json').read_text())
    request(MANAGER + '/api/v2/silence/' + receipt['silence'])
    print(json.dumps({'subscription_removed': True, 'shared_receivers_and_state_retained': True}))


def run():
    project = 'notification-proof-' + uuid.uuid4().hex[:10]
    networks = subprocess.run(['docker', 'network', 'ls', '-q'], check=True,
                              capture_output=True, text=True).stdout.split()
    occupied = []
    if networks:
        rows = json.loads(subprocess.run(['docker', 'network', 'inspect', *networks], check=True,
                                        capture_output=True, text=True).stdout)
        occupied = [ipaddress.ip_network(config['Subnet']) for row in rows
                    for config in ((row.get('IPAM') or {}).get('Config') or []) if config.get('Subnet')]
    subnet = next((ipaddress.ip_network(f'10.245.{index}.0/24') for index in range(234, 244)
                   if not any(ipaddress.ip_network(f'10.245.{index}.0/24').overlaps(other)
                              for other in occupied if other.version == 4)), None)
    if subnet is None: raise RuntimeError('No isolated notification fixture subnet available')
    environment = dict(os.environ, NOTIFICATION_PROOF_SUBNET=str(subnet))
    compose = ['docker', 'compose', '-p', project, '-f',
               str(ROOT / 'ansible/playbooks/observability/tests/compose.notifications-proof.yaml')]
    def command(*args):
        result = subprocess.run([*compose, *args], cwd=ROOT, env=environment,
                                capture_output=True, text=True, timeout=300)
        if result.returncode:
            detail = result.stdout.strip().splitlines()[-1:] + result.stderr.strip().splitlines()[-1:]
            raise RuntimeError('Isolated notification proof failed: ' + ' '.join(args) + '; ' + ' '.join(detail))
        if args[0] == 'run': print(result.stdout.strip())
    try:
        command('up', '--build', '-d', 'alertmanager', 'receiver')
        command('run', '--rm', '-T', '--no-deps', 'proof', 'verify')
        command('up', '-d', '--no-deps', '--force-recreate', 'alertmanager')
        command('run', '--rm', '-T', '--no-deps', 'proof', 'restart')
        command('run', '--rm', '-T', '--no-deps', 'prepare', 'remove')
        command('run', '--rm', '-T', '--no-deps', 'proof', 'removal')
    finally:
        command('down', '--volumes', '--remove-orphans')


if __name__ == '__main__':
    try:
        {'prepare': prepare, 'verify': verify, 'restart': verify_restart,
         'remove': remove_subscription, 'removal': verify_removal, 'run': run}[sys.argv[1]]()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else
                         'Notification fixture failed (' + type(error).__name__ + '); private diagnostics withheld') from None
