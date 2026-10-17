// Read-only HTTP/2 connection reuse proof; private endpoints arrive on stdin.
import http2 from 'node:http2';
import fs from 'node:fs';
import net from 'node:net';

let stage = 'input';
try {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const {zone, gateway_address: address} = input;
  if (Object.keys(input).sort().join(',') !== 'gateway_address,zone' ||
      typeof zone !== 'string' || zone.length > 253 ||
      !zone.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ||
      net.isIP(address) !== 4 || Number(address.split('.')[0]) !== 100 ||
      Number(address.split('.')[1]) < 64 || Number(address.split('.')[1]) > 127)
    throw new Error('Invalid private routing inputs');
  const login = 'login.' + zone;
  const targets = [
    {host: login, path: '/realms/platform/account/', status: 200},
    {host: 'cd.internal.' + zone, path: '/', status: 200},
    {host: 'identity-admin.internal.' + zone, path: '/', status: 302},
    {host: login, path: '/admin/realms', status: 404},
  ];
  let checked = 0;
  for (const origin of targets.slice(0, 3)) {
    stage = 'TLS connection';
    const session = http2.connect('https://' + origin.host, {
      lookup: (_host, options, callback) => options.all
        ? callback(null, [{address, family: 4}]) : callback(null, address, 4),
    });
    session.setTimeout(15000, () => session.destroy(new Error('Routing timeout')));
    try {
      await new Promise((resolve, reject) => {
        session.once('connect', resolve);
        session.on('error', reject);
      });
      if (session.alpnProtocol !== 'h2') throw new Error('HTTP/2 unavailable');
      for (const target of targets) {
        stage = 'coalesced request ' + checked;
        const status = await new Promise((resolve, reject) => {
          const request = session.request({':method': 'GET', ':authority': target.host, ':path': target.path});
          let bytes = 0, status;
          request.once('response', headers => { status = headers[':status']; });
          request.on('data', chunk => {
            bytes += chunk.length;
            if (bytes > 65536) request.destroy(new Error('Response too large'));
          });
          request.once('end', () => resolve(status));
          request.once('error', reject);
          request.setTimeout(10000, () => request.destroy(new Error('Request timeout')));
          request.end();
        });
        if (status !== target.status) throw new Error('Unexpected route status');
        checked++;
      }
    } finally {
      session.destroy();
    }
  }
  console.log(JSON.stringify({private_http2_connection_reuse: true, verified_tls: true,
    coalesced_requests_checked: checked, canonical_admin_api_denied: true, credentials_used: false}));
} catch (error) {
  console.error('Private routing proof failed at ' + stage + ': ' + error.name);
  process.exitCode = 1;
}
