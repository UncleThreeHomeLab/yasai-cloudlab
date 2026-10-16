"""Native, free Grafana authentication and local telemetry policy."""
import json
from pathlib import Path
from urllib.parse import urlsplit, quote

from automation.identity.integrations import issuer
from automation.identity.configuration import exact_url

ROOT = Path(__file__).resolve().parents[2]
POLICY = json.loads((ROOT / 'platform/observability/policy.json').read_text())
ROLE_PATH = "contains(groups[*], '/platform-admin') && 'Admin' || contains(groups[*], '/developer') && 'Editor' || contains(groups[*], '/viewer') && 'Viewer' || ''"


def audit_rules():
    checks = [
        ('KeycloakLoginFailures', 'sum by (realm) (increase(cloudlab_keycloak_login_failures_total[10m])) >= 10', '1m',
         'Repeated realm login failures', 'Inspect redacted realm events. Do not export credentials or user identifiers.'),
        ('KeycloakAdminChange', 'sum by (realm) (increase(cloudlab_keycloak_admin_events_total[5m])) > 0', '0s',
         'Realm administrative change observed', 'Review intended configuration or maintenance against redacted operation events.'),
        ('KeycloakAuditIncomplete', 'cloudlab_keycloak_audit_incomplete > 0 and '
         '(cloudlab_keycloak_health_last_success_seconds == on (realm) group_left '
         'max by (realm) (cloudlab_keycloak_health_last_success_seconds))', '0s',
         'Realm audit window may be truncated', 'A closed five-minute window reached its 1000-event cap. Inspect event volume and the bounded audit collector.'),
        ('KeycloakHealthJobFailed', 'kube_job_status_failed{namespace="cloudlab-identity",job_name=~"identity-health-.*"} > 0', '1m',
         'Realm health or audit job failed', 'Inspect private job status. Missing evidence is never healthy.'),
    ]
    for realm in ('platform', 'applications'):
        selector = 'cloudlab_keycloak_health_last_success_seconds{realm="' + realm + '"}'
        checks.append(('KeycloakEvidenceStale' + realm.title(), '(time() - max(' + selector + ') > 900) or absent(' + selector + ')',
            '5m', 'Realm health evidence stale: ' + realm, 'Check scheduled health job and Alloy. No complete poll observed within 15 minutes.'))
    return {'groups': [{'name': 'identity-evidence', 'interval': '30s', 'rules': [
        {'alert': name, 'expr': expression, 'for': duration, 'labels': {'severity': 'warning', 'service': 'keycloak'},
         'annotations': {'summary': summary, 'description': description}}
        for name, expression, duration, summary, description in checks]}]}


def grafana(identity_issuer, origin):
    issuer(identity_issuer)
    callback = exact_url(origin + '/login/generic_oauth')
    if urlsplit(callback).path != '/login/generic_oauth' or '.internal.' not in urlsplit(origin).hostname:
        raise ValueError('Grafana requires its exact private HTTPS origin')
    protocol = identity_issuer + '/protocol/openid-connect'
    return {'client': {'id': 'grafana', 'public': False, 'audience': 'grafana',
                       'callbacks': [callback], 'logout_callbacks': [origin + '/login'],
                       'scopes': ['profile', 'email']},
            'ini': {
                'server': {'root_url': origin},
                'dashboards': {'default_home_dashboard_path': '/var/lib/grafana/dashboards/cloudlab/lab-overview.json'},
                'security': {'cookie_secure': True, 'cookie_samesite': 'lax', 'disable_gravatar': True,
                             'secret_key': '$__file{/etc/secrets/grafana-emergency/secret_key}'},
                'users': {'allow_sign_up': False},
                'analytics': {'reporting_enabled': False, 'check_for_updates': False, 'check_for_plugin_updates': False},
                'plugins': {'preinstall_disabled': True, 'preinstall': '', 'preinstall_sync': '',
                            'public_key_retrieval_disabled': True, 'plugin_admin_enabled': False},
                'auth': {'disable_login_form': False, 'oauth_allow_insecure_email_lookup': False,
                         'login_maximum_lifetime_duration': '5m', 'login_maximum_inactive_lifetime_duration': '5m',
                         'token_rotation_interval_minutes': 1, 'signout_redirect_url':
                         protocol + '/logout?post_logout_redirect_uri=' + quote(origin + '/login', safe='')},
                'auth.anonymous': {'enabled': False},
                'auth.generic_oauth': {'enabled': True, 'name': 'Keycloak', 'client_id': 'grafana',
                    'client_secret': '$__file{/etc/secrets/grafana-oidc/client_secret}',
                    'auth_url': protocol + '/auth', 'token_url': protocol + '/token', 'api_url': protocol + '/userinfo',
                    'scopes': 'openid profile email', 'use_pkce': True, 'use_refresh_token': True,
                    'allow_sign_up': True, 'auto_login': False, 'login_attribute_path': 'sub',
                    'role_attribute_path': ROLE_PATH, 'role_attribute_strict': True,
                    'allow_assign_grafana_admin': False, 'skip_org_role_sync': False},
                'unified_alerting': {'enabled': False}, 'alerting': {'enabled': False},
            }}


def kiali(identity_issuer, origin):
    issuer(identity_issuer)
    callback = exact_url(origin + '/kiali')
    if urlsplit(callback).path != '/kiali' or '.internal.' not in urlsplit(origin).hostname:
        raise ValueError('Kiali requires its exact private HTTPS origin')
    return {'id': 'kiali', 'public': False, 'audience': 'kiali', 'callbacks': [callback], 'scopes': ['profile', 'email']}
