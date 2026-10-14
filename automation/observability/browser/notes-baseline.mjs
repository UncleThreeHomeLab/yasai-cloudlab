// Disposable applications viewer only; credentials and JWT stay in process memory.
import {chromium} from 'playwright';
import readline from 'node:readline';
import net from 'node:net';

const listener = net.createServer();
listener.listen(5055, '0.0.0.0');
const connection = await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('Controller connection unavailable')), 120000);
  listener.once('connection', socket => {clearTimeout(timer); listener.close(); resolve(socket);});
  listener.once('error', reject);
});
const lines = readline.createInterface({input: connection, terminal: false})[Symbol.asyncIterator]();
let browser;
let stage = 'input';
try {
  const input = JSON.parse((await lines.next()).value);
  if (!/^[a-f0-9]{32}$/.test(input.nonce) || input.username !== 'proof-' + input.nonce ||
      typeof input.password !== 'string' || input.password.length < 48 ||
      !/^https:\/\/[a-z0-9.-]+$/.test(input.origin) ||
      !/^https:\/\/[a-z0-9.-]+\/realms\/applications$/.test(input.issuer)) throw new Error('Invalid scope');
  browser = await chromium.launch();
  const context = await browser.newContext();
  context.setDefaultTimeout(60000);
  // Tailnet split DNS resolves the canonical issuer to a private address.
  await context.grantPermissions(['local-network-access'], {origin: input.origin});
  const page = await context.newPage();
  // The browser login must not manufacture user SLO samples.
  await page.route(input.origin + '/api/notes', route => route.fulfill({
    status: 200, contentType: 'application/json', body: '{"notes":[]}'}));
  page.on('dialog', dialog => dialog.accept('disposable-release-viewer'));
  const issued = page.waitForResponse(response => response.url() === input.issuer + '/protocol/openid-connect/token' &&
    response.request().method() === 'POST', {timeout: 120000});
  stage = 'canonical application';
  await page.goto(input.origin);
  await page.getByRole('button', {name: 'Sign in', exact: true}).click();
  stage = 'disposable password';
  await page.getByLabel('Username', {exact: false}).fill(input.username);
  await page.getByLabel('Password', {exact: true}).fill(input.password);
  await page.getByRole('button', {name: 'Sign In', exact: true}).click();
  stage = 'disposable MFA';
  await page.waitForLoadState('domcontentloaded');
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {protocol: 'ctap2', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true}});
  await page.getByRole('button', {name: /Register/}).click();
  stage = 'code exchange';
  const response = await issued;
  if (response.status() !== 200) throw new Error('Code exchange rejected');
  const result = await response.json();
  if (typeof result.access_token !== 'string' || result.access_token.length > 16384) throw new Error('Token unavailable');
  const claims = JSON.parse(Buffer.from(result.access_token.split('.')[1], 'base64url').toString());
  if (claims.iss !== input.issuer || claims.exp < Date.now() / 1000 + 150 ||
      !Array.isArray(claims.roles) || !claims.roles.includes('reader') ||
      claims.roles.includes('writer') || claims.roles.includes('operator')) throw new Error('Viewer token scope rejected');
  connection.write(JSON.stringify({access_token: result.access_token, viewer_mfa: true}) + '\n');
  await lines.next();
} catch {
  connection.write(JSON.stringify({failed: true, stage}) + '\n');
  process.exitCode = 1;
} finally {
  if (browser) await browser.close();
  connection.end();
}
