// Explicit, credential-free browser fixture. Input origins come from contract.hostname.
import assert from 'node:assert/strict';
import {readFileSync, readSync, mkdtempSync, rmSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createServer} from 'node:https';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createRequire} from 'node:module';
const require = createRequire('/proof/package.json');
const {chromium} = require('playwright');
let origins;
try {
  const input = Buffer.alloc(1025);
  let size = 0;
  while (size < input.length) {
    const count = readSync(0, input, size, input.length - size, null);
    if (!count) break;
    size += count;
  }
  if (size > 1024) throw new Error();
  origins = JSON.parse(input.subarray(0, size).toString('utf8'));
  if (!Array.isArray(origins) || origins.length !== 2 || origins[0] === origins[1] ||
      origins.some(origin => typeof origin !== 'string' ||
        !/^https:\/\/preview-[a-f0-9]{32}\.internal\.example\.invalid$/.test(origin))) throw new Error();
} catch {
  console.error('Synthetic preview origins rejected; input withheld');
  process.exit(1);
}
const directory = mkdtempSync(join(tmpdir(), 'preview-browser-'));
const key = join(directory, 'key.pem');
const cert = join(directory, 'cert.pem');
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=fixture.invalid',
  '-keyout', key, '-out', cert], {stdio: 'ignore'});
const crossRequests = [];
const server = createServer({key: readFileSync(key), cert: readFileSync(cert)}, (request, response) => {
  if (request.headers.origin) crossRequests.push(request.headers.origin);
  response.writeHead(200, {'Content-Type': 'text/html'});
  response.end('<html><body>synthetic private fixture</body></html>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
origins = origins.map(origin => origin + ':' + port);
let browser;
try {
  browser = await chromium.launch({headless: true, args: ['--no-proxy-server',
    '--host-resolver-rules=MAP *.internal.example.invalid 127.0.0.1', '--ignore-certificate-errors']});
  const context = await browser.newContext({ignoreHTTPSErrors: true});
  context.setDefaultTimeout(15000);
  const first = await context.newPage();
  const second = await context.newPage();
  await first.goto(origins[0]);
  await first.evaluate(() => {localStorage.setItem('preview', 'A'); document.cookie = 'preview=A; Secure; SameSite=Strict; Path=/';});
  await second.goto(origins[1]);
  assert.match(await second.evaluate(async () => (await (await fetch(location.origin)).text())), /synthetic private fixture/);
  assert.deepEqual(await second.evaluate(() => [localStorage.getItem('preview'), document.cookie]), [null, '']);
  await second.evaluate(() => localStorage.setItem('preview', 'B'));
  assert.equal(await first.evaluate(() => localStorage.getItem('preview')), 'A');
  const isolated = await first.evaluate(async other => {
    const frame = document.createElement('iframe');
    frame.src = other;
    const loaded = new Promise(resolve => frame.onload = resolve);
    document.body.append(frame);
    await Promise.race([loaded, new Promise((_, reject) => setTimeout(() => reject(new Error('fixture frame timed out')), 10000))]);
    let domDenied = false;
    try {void frame.contentWindow.document.body.innerText;} catch {domDenied = true;}
    let responseDenied = false;
    try {await (await fetch(other, {signal: AbortSignal.timeout(10000)})).text();} catch {responseDenied = true;}
    return {domDenied, responseDenied};
  }, origins[1]);
  assert.deepEqual(isolated, {domDenied: true, responseDenied: true});
  assert.ok(crossRequests.includes(origins[0]));
  console.log(JSON.stringify({distinct_origins: true, dom_storage_response_isolation: true, host_cookie_isolation: true, live_identity_tested: false}));
} finally {
  if (browser) await browser.close();
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  rmSync(directory, {recursive: true});
}
