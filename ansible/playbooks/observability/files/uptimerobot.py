"""Independent public monitoring using the authorized UptimeRobot Free account."""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

PREFIX = 'cloudlab-owned:'
API_ROOT = 'https://api.uptimerobot.com/v3/'
MAX_RESPONSE = 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class API:
    def __init__(self, token):
        if not isinstance(token, str) or not token or any(c.isspace() for c in token):
            raise ValueError('Independent monitoring requires its vault API key')
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())
        self.last_request = None

    def request(self, method, path, value=None):
        # Free API allows ten requests/minute. No automatic mutation retries.
        if self.last_request is not None:
            time.sleep(max(0, 6.1 - (time.monotonic() - self.last_request)))
        self.last_request = time.monotonic()
        request = urllib.request.Request(API_ROOT + path, method=method,
            data=None if value is None else json.dumps(value).encode(),
            headers={'Authorization': 'Bearer ' + self.token,
                     'Content-Type': 'application/json', 'Accept': 'application/json',
                     'User-Agent': 'CloudLab-Independent-Monitor/1.0'})
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise ValueError('Independent monitoring response exceeds its limit')
            return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            raise RuntimeError('Independent monitoring API rejected request (HTTP ' + str(status) +
                               '); inspect provider account before retrying') from None
        except (urllib.error.URLError, TimeoutError, ValueError):
            raise RuntimeError('Independent monitoring API unavailable; mutation outcome may require inspection') from None


def contact(api, expected=None):
    user = api.request('GET', 'user/me')
    subscription = user.get('activeSubscription') or {}
    # Fail closed if eligibility changes; never start a trial or upgrade.
    if str(subscription.get('plan', '')).upper() != 'FREE' or user.get('monitorLimit') != 50:
        raise RuntimeError('Independent monitoring requires the accepted Free account and 50-monitor limit')
    email = user.get('email')
    if not isinstance(email, str) or '@' not in email:
        raise RuntimeError('Registered monitoring email unavailable')
    contacts = api.request('GET', 'user/alert-contacts')
    if not isinstance(contacts, list):
        raise RuntimeError('Independent notification contacts unavailable')
    matches = [row for row in contacts if row.get('type') == 'Email' and
               row.get('value', '').casefold() == email.casefold() and row.get('status') == 'Active']
    if len(matches) != 1 or type(matches[0].get('id')) is not int:
        raise RuntimeError('Require one active contact matching the registered email')
    identifier = matches[0]['id']
    if expected is not None and expected != identifier:
        raise RuntimeError('Configured notification contact differs from the registered email')
    return identifier


def public_url(value):
    if (not isinstance(value, str) or not value.isascii() or
            any(ord(c) <= 32 or ord(c) == 127 or c in '*\\' for c in value)):
        raise ValueError('Monitor requires an exact public HTTPS URL')
    try:
        parsed = urllib.parse.urlsplit(value)
        invalid = parsed.port not in (None, 443)
    except ValueError:
        invalid = True
        parsed = None
    if (invalid or parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or
            parsed.password is not None or parsed.query or parsed.fragment or
            not parsed.path.startswith('/') or '%' in parsed.path or '..' in parsed.path or
            parsed.hostname.endswith(('.invalid', '.localhost', '.local'))):
        raise ValueError('Monitor requires an exact public HTTPS URL without credentials or query')
    import ipaddress
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if '.' not in parsed.hostname or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-' for c in parsed.hostname):
            raise ValueError('Monitor requires a public DNS hostname')
    else:
        raise ValueError('Monitor requires a public DNS hostname')
    if '.internal.' in parsed.hostname:
        raise ValueError('Hosted monitor cannot access private services')
    return value


def probe(url, expected_status):
    """Require the real uncached endpoint before enabling hosted notifications."""
    public_url(url)
    request = urllib.request.Request(url, headers={'User-Agent': 'CloudLab-Independent-Preflight/1.0'})
    opener = urllib.request.build_opener(NoRedirect())
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    except (urllib.error.URLError, TimeoutError):
        raise RuntimeError('Public monitor endpoint unavailable; no monitor mutation') from None
    with response:
        raw = response.read(1025)
        try:
            value = json.loads(raw) if len(raw) <= 1024 else None
        except ValueError:
            value = None
        if (response.code != expected_status or value != {'ready': expected_status == 200} or
                response.headers.get('Cache-Control') != 'no-store' or
                str(response.headers.get('CF-Cache-Status', '')).upper() in ('HIT', 'STALE', 'UPDATING', 'REVALIDATED')):
            raise RuntimeError('Public monitor endpoint is not the expected uncached health response; no monitor mutation')
    return {'public_endpoint': True, 'uncached': True}


def desired(key, url, identifier):
    if key not in ('notes-health', 'notification-proof') or type(identifier) is not int or identifier <= 0:
        raise ValueError('Monitor scope or contact is invalid')
    return {'friendlyName': PREFIX + key, 'type': 'HTTP', 'url': public_url(url),
            'interval': 300, 'timeout': 15, 'httpMethodType': 'GET', 'authType': 'NONE',
            'successHttpResponseCodes': ['200'], 'followRedirections': False,
            'checkSSLErrors': True, 'sslExpirationReminder': False,
            'domainExpirationReminder': False,
            'assignedAlertContacts': [{'alertContactId': identifier, 'threshold': 0, 'recurrence': 0}],
            'config': {'applicationErrorRetries': 1}}


def monitors(api):
    document = api.request('GET', 'monitors?limit=50')
    if (not isinstance(document, dict) or not isinstance(document.get('data'), list) or
            len(document['data']) > 50 or document.get('nextLink') is not None):
        raise RuntimeError('Monitoring inventory is incomplete; refuse mutation')
    return document['data']


def owned(rows, key):
    matches = [row for row in rows if row.get('friendlyName') == PREFIX + key]
    if len(matches) > 1:
        raise RuntimeError('Duplicate owned monitor names; refuse mutation')
    if matches and (type(matches[0].get('id')) is not int or matches[0].get('type') != 'HTTP'):
        raise RuntimeError('Owned monitor has incompatible identity or type')
    return matches[0] if matches else None


def normalized(row):
    result = {key: row.get(key) for key in ('friendlyName', 'type', 'url', 'interval', 'timeout',
        'httpMethodType', 'authType', 'successHttpResponseCodes', 'followRedirections',
        'checkSSLErrors', 'sslExpirationReminder', 'domainExpirationReminder')}
    contacts = row.get('assignedAlertContacts')
    if not isinstance(contacts, list):
        raise RuntimeError('Owned monitor notification configuration unavailable')
    result['assignedAlertContacts'] = sorted([
        {key: entry.get(key) for key in ('alertContactId', 'threshold', 'recurrence')}
        for entry in contacts], key=lambda entry: entry.get('alertContactId') or 0)
    result['config'] = {'applicationErrorRetries': (row.get('config') or {}).get('applicationErrorRetries')}
    return result


def reconcile(api, key, url, identifier, *, apply=False, allow_fixture_change=False):
    target = desired(key, url, identifier)
    current = owned(monitors(api), key)
    if current and key == 'notification-proof':
        parsed = urllib.parse.urlsplit(target['url'])
        allowed = ['https://' + parsed.netloc + '/monitoring-proof/' + state for state in ('ready', 'failed')]
        if target['url'] not in allowed or current['url'] not in allowed:
            raise RuntimeError('Disposable monitor scope changed; refuse mutation')
    if current and current['url'] != target['url'] and not (key == 'notification-proof' and allow_fixture_change):
        raise RuntimeError('Existing monitor endpoint changed; explicit migration required')
    if current and current.get('status') == 'PAUSED':
        raise RuntimeError('Owned monitor is paused; resume requires explicit supported lifecycle action')
    changed = current is None or normalized(current) != target or current.get('status') == 'PAUSED'
    if changed and apply:
        if current is None:
            # Re-list on the next run after an uncertain POST; never blindly retry.
            api.request('POST', 'monitors', target)
        else:
            api.request('PATCH', 'monitors/' + str(current['id']), target)
        # Provider reads can lag a successful write. Observe; never repeat creates.
        converged = False
        for attempt in range(3):
            observed = owned(monitors(api), key)
            if observed is not None and normalized(observed) == target and observed.get('status') != 'PAUSED':
                converged = True
                break
        if not converged:
            raise RuntimeError('Independent monitor configuration did not converge')
    return {'configured': not changed or apply, 'changes': int(changed), 'notifications': 'registered-email-only',
            'interval_seconds': 300, 'automatic_lab_dependency': False}


def remove_fixture(api, expected_url):
    current = owned(monitors(api), 'notification-proof')
    if not current:
        return {'removed': False, 'already_absent': True}
    if current['url'] != public_url(expected_url):
        raise RuntimeError('Fixture endpoint changed; deletion refused')
    api.request('DELETE', 'monitors/' + str(current['id']))
    if owned(monitors(api), 'notification-proof'):
        raise RuntimeError('Disposable monitor deletion did not converge')
    return {'removed': True}
