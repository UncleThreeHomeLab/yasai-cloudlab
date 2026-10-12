import unittest

from automation.connectivity.service_dns import desired


class ServiceDnsTests(unittest.TestCase):
    def test_private_publication_and_removal_preserve_unrelated_records(self):
        payload = {'zone': 'internal.example.invalid', 'names': ['cd', 's3'], 'unchanged': 'retained'}
        exposure = {'class':'private','access':'tailnet','hostname':'fixture.internal.example.invalid'}
        published = desired(payload, exposure, ['cd'], published=True)
        self.assertEqual(published['names'], ['cd','fixture','s3'])
        self.assertEqual(desired(published, exposure, ['cd'], published=False), payload)
        self.assertEqual(payload['names'], ['cd','s3'])
        for hostname in ('cd.internal.example.invalid','fixture.internal.other.invalid','s3.internal.example.invalid'):
            with self.assertRaises(ValueError): desired(payload, dict(exposure,hostname=hostname), ['cd'], published=False)
