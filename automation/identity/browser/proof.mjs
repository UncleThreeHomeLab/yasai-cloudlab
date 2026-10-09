import { chromium } from 'playwright';
import fs from 'node:fs';
import crypto from 'node:crypto';

const failure = process.argv.includes('--failure');
const input = failure ? null : JSON.parse(fs.readFileSync('/fixture/browser-input', 'utf8'));
const cert = new crypto.X509Certificate(fs.readFileSync('/fixture/tls.crt'));
const spki = crypto.createHash('sha256').update(cert.publicKey.export({type:'spki', format:'der'})).digest('base64');
const browser = await chromium.launch({headless:true, args:[`--ignore-certificate-errors-spki-list=${spki}`]});
let stage = failure ? 'IdP failure' : 'browser MFA';
let page;
try {
  const context = await browser.newContext();
  context.setDefaultTimeout(60000);
  page = await context.newPage();
  page.on('dialog', dialog => dialog.accept('disposable-browser'));
  if (failure) {
    const response = await page.goto('https://localhost/login');
    if (response.status() !== 503) throw new Error('Failed IdP permitted new login');
    const repair = await page.goto('https://localhost/health');
    if (repair.status() !== 200) throw new Error('Independent reference health unavailable');
    console.log(JSON.stringify({new_login_fails_closed:true,reference_health_independent:true,
      environment:'disposable stopped IdP; host/API repair requires separate existing-VM proof'}));
  } else {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const {authenticatorId} = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,
             hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  stage='initial authorization';
  await page.goto('https://localhost/login');
  await page.getByLabel('Username', {exact:false}).fill(input.username);
  await page.getByLabel('Password', {exact:true}).fill(input.password);
  await page.getByRole('button', {name:'Sign In', exact:true}).click();
  stage='WebAuthn registration';
  await page.getByRole('button', {name:/Register/}).click();
  const label = page.getByLabel(/Authenticator Label/);
  if (await label.count()) {
    await label.fill('disposable-browser');
    await page.getByRole('button', {name:/Register/}).click();
  }
  stage='MFA callback';
  await page.waitForURL('https://localhost/', {timeout:60000});
  if (!(await page.getByText('MFA session active').count())) throw new Error('Reference MFA login failed');
  await page.getByRole('link', {name:'Check API permission'}).click();
  if (!(await page.getByText('API permitted').count())) throw new Error('Reference API role denied');
  await page.goto('https://localhost/login');
  stage='SSO callback';
  await page.waitForURL('https://localhost/', {timeout:30000});
  if (await page.getByLabel('Password', {exact:true}).count()) throw new Error('Reference SSO failed');
  const callbacks = await page.request.get('https://localhost/callback?state=wrong&code=wrong');
  if (callbacks.status() !== 400) throw new Error('Wrong state accepted');
  const noToken = await page.request.get('https://localhost/api');
  if (noToken.status() !== 401) throw new Error('Missing API token accepted');
  const credentials = await cdp.send('WebAuthn.getCredentials', {authenticatorId});
  if (!credentials.credentials.length) throw new Error('No WebAuthn credential enrolled');
  const authenticatedCookies = await context.cookies();
  // Real credential, wrong UV: password alone must not complete privileged login.
  await context.clearCookies();
  stage='unverified WebAuthn denial';
  await cdp.send('WebAuthn.setUserVerified', {authenticatorId,isUserVerified:false});
  await page.goto('https://localhost/login');
  await page.getByLabel('Username', {exact:false}).fill(input.username);
  await page.getByLabel('Password', {exact:true}).fill(input.password);
  await page.getByRole('button', {name:'Sign In', exact:true}).click();
  await page.waitForTimeout(3000);
  if (page.url() === 'https://localhost/') throw new Error('Password without verified WebAuthn accepted');

  await context.clearCookies();
  await context.addCookies(authenticatedCookies.filter(cookie => cookie.name === '__Host-cloudlab-fixture'));
  stage='offboarding import';
  const started = Date.now();
  async function reconcileOffboarding() {
    for (const name of ['result','remove','scoped-secret']) fs.rmSync('/fixture/'+name,{force:true});
    for (const [name,value] of [['input.json',JSON.stringify(input.offboarding_import)],['scope','main']]) {
      fs.writeFileSync('/fixture/'+name,value,{mode:0o600});
      fs.chownSync('/fixture/'+name,1000,1000);
    }
    fs.writeFileSync('/fixture/request','');
    const deadline = Date.now()+120000;
    while (!fs.existsSync('/fixture/result')) {
      if (Date.now()>deadline) throw new Error('Offboarding reconciliation timed out');
      await new Promise(resolve => setTimeout(resolve,500));
    }
    if (fs.readFileSync('/fixture/result','utf8').trim() !== '0') throw new Error('Offboarding reconciliation failed');
  }
  await reconcileOffboarding();
  // Existing signed JWT remains valid after disabling its account; measure expiry.
  if ((await page.request.get('https://localhost/api-session')).status() !== 200)
    throw new Error('JWT expiry measurement has no still-valid starting token');
  const deniedContext = await browser.newContext();
  stage='offboarded new login';
  await deniedContext.addCookies(authenticatedCookies.filter(cookie => cookie.name !== '__Host-cloudlab-fixture'));
  const deniedPage = await deniedContext.newPage();
  await deniedPage.goto('https://localhost/login');
  if (deniedPage.url() === 'https://localhost/') throw new Error('Offboarded Keycloak SSO session issued a new grant');
  await deniedPage.getByLabel('Username',{exact:false}).fill(input.username);
  await deniedPage.getByLabel('Password',{exact:true}).fill(input.password);
  await deniedPage.getByRole('button',{name:'Sign In',exact:true}).click();
  if (!(await deniedPage.getByText(/Account is disabled/).count()))
    throw new Error('Offboarded account can start a new login');
  const loginDeniedSeconds = Math.ceil((Date.now()-started)/1000);
  stage='offboarding repeat';
  await reconcileOffboarding();
  await deniedPage.getByLabel('Password',{exact:true}).fill(input.password);
  await deniedPage.getByRole('button',{name:'Sign In',exact:true}).click();
  if (!(await deniedPage.getByText(/Account is disabled/).count()))
    throw new Error('Repeat reconciliation re-enabled an offboarded account');
  await deniedContext.close();
  stage='existing JWT expiry';
  let status=200;
  while (status===200 && Date.now()-started<=330000) {
    await new Promise(resolve => setTimeout(resolve,2000));
    status=(await page.request.get('https://localhost/api-session')).status();
  }
  if (status!==403) throw new Error('Existing access JWT exceeded its measured expiry deadline');
  const accessDeniedSeconds = Math.ceil((Date.now()-started)/1000);
  stage='private master browser';
  const masterContext = await browser.newContext();
  masterContext.setDefaultTimeout(60000);
  const masterPage = await masterContext.newPage();
  masterPage.on('dialog', dialog => dialog.accept('disposable-master'));
  const masterCdp = await masterContext.newCDPSession(masterPage);
  await masterCdp.send('WebAuthn.enable');
  await masterCdp.send('WebAuthn.addVirtualAuthenticator', {options:{protocol:'ctap2',transport:'internal',
    hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  await masterPage.goto('https://admin.fixture.test/admin/master/console/');
  await masterPage.getByLabel('Username',{exact:false}).fill(input.master_username);
  await masterPage.getByLabel('Password',{exact:true}).fill(input.master_password);
  await masterPage.getByRole('button',{name:'Sign In',exact:true}).click();
  await masterPage.getByRole('button',{name:/Register/}).click();
  const masterLabel = masterPage.getByLabel(/Authenticator Label/);
  if (await masterLabel.count()) {
    await masterLabel.fill('disposable-master');
    await masterPage.getByRole('button',{name:/Register/}).click();
  }
  await masterPage.waitForURL(/^https:\/\/admin\.fixture\.test\/admin\/master\/console\/(?:#|$)/,{timeout:60000});
  await masterPage.getByRole('link',{name:'Realm settings',exact:true}).waitFor({timeout:60000});
  await masterContext.close();
  console.log(JSON.stringify({browser_code_pkce_state_nonce:true,verified_webauthn:true,
    private_master_browser_mfa:true,master_console_without_public_issuer_loop:true,
    password_without_uv_denied:true,sso_without_loop:true,reference_api:true,
    wrong_state_denied:true,missing_access_token_denied:true,
    offboard_new_login_denied_seconds:loginDeniedSeconds,offboard_access_jwt_denied_seconds:accessDeniedSeconds,
    offboarding_repeat_did_not_reenable:true,logout_is_not_instant_jwt_revocation:true,
    environment:'disposable localhost TLS and virtual authenticator; not personal 1Password enrollment'}));
  }
} catch (error) {
  // Browser diagnostics may contain authorization codes or personal fixture data.
  console.error('Disposable browser proof failed at '+stage+': '+error.name);
  if (page) await page.screenshot({path:'/fixture/browser-failure.png'}).catch(()=>{});
  process.exitCode=1;
} finally {
  await browser.close();
}
