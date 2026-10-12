import copy
import json
import unittest

from automation.services.external import declarations, guarded_plan
from automation.services.tests.fixtures import definition


class ExternalTests(unittest.TestCase):
    def value(self):
        value = definition()
        value['exposure'] = {'class': 'public', 'hostname': 'service.example.invalid', 'access': 'public', 'path': '/', 'port': 8080}
        return value

    def test_publication_stages_preserve_shared_inputs_and_cannot_publish_first(self):
        initial = {'routes': {'shared': {'hostname': 'shared.example.invalid'}}, 'applications': {'unchanged': {'id': 'retained'}}}
        value = self.value()
        with self.assertRaises(ValueError): declarations(value, initial, operation='publish', origin='https://origin.example.invalid')
        ready = declarations(value, initial, operation='ready', origin='https://origin.example.invalid')
        routed = declarations(value, ready, operation='route', origin='https://origin.example.invalid')
        published = declarations(value, routed, operation='publish', origin='https://origin.example.invalid')
        self.assertEqual(initial['routes'], published['routes'])
        self.assertEqual(initial['applications'], published['applications'])
        self.assertEqual(declarations(value, published, operation='publish', origin='https://origin.example.invalid'), published)
        with self.assertRaises(ValueError): declarations(value, published, operation='withdraw-route', origin='https://origin.example.invalid')
        withdrawn = declarations(value, published, operation='withdraw-dns', origin='https://origin.example.invalid')
        retired = declarations(value, withdrawn, operation='withdraw-route', origin='https://origin.example.invalid')
        self.assertFalse(retired['service_exposures']['service_synthetic']['routed'])
        changed = copy.deepcopy(value)
        changed['exposure']['access'] = 'human'
        with self.assertRaises(ValueError): declarations(changed, published, operation='route', origin='https://origin.example.invalid', application='approved')

    def test_plan_guard_refuses_shared_deletion_and_unrelated_tunnel_change(self):
        value = self.value()
        unrelated = {'address': 'cloudflare_dns_record.publication["shared"]', 'mode': 'managed',
                     'change': {'actions': ['delete'], 'before': {'name': 'shared.example.invalid'}}}
        with self.assertRaises(ValueError): guarded_plan({'resource_changes': [unrelated]}, value, 'withdraw-dns')
        dns = {'address': 'cloudflare_dns_record.service_publication["service_synthetic"]', 'mode': 'managed',
               'change': {'actions': ['create'], 'after': {'name': value['exposure']['hostname']}}}
        guarded_plan({'resource_changes': [dns]}, value, 'publish')
        before = {'id':'same','config':{'ingress':[{'hostname':'shared.example.invalid','service':'https://shared.example.invalid'},{'service':'http_status:404'}]}}
        after = copy.deepcopy(before)
        after['config']['ingress'].insert(1, {'hostname':value['exposure']['hostname'],'service':'https://origin.example.invalid','origin_request':{
            'no_tls_verify':False,'origin_server_name':value['exposure']['hostname'],'http_host_header':value['exposure']['hostname']}})
        tunnel = {'address':'cloudflare_zero_trust_tunnel_cloudflared_config.routing','mode':'managed',
                  'change':{'actions':['update'],'before':before,'after':after}}
        guarded_plan({'resource_changes':[tunnel]},value,'route')
        after['config']['ingress'][0]['service']='https://wrong.example.invalid'
        with self.assertRaises(ValueError): guarded_plan({'resource_changes':[tunnel]},value,'route')
