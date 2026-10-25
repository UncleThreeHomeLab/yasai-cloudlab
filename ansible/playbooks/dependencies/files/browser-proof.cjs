// Runs only in the recorded credential-free native browser image.
const fs = require('node:fs');
const {spawnSync} = require('node:child_process');
let phase = 'plan';
try {
  const plan = JSON.parse(fs.readFileSync('/plan.json'));
  phase = 'record';
  const record = JSON.parse(fs.readFileSync('/browser-toolchain.json'));
  phase = 'identity';
  if (record.operation !== plan.operation || record.role !== 'identity-browser' ||
      record.imageId !== process.env.DEPENDENCY_BROWSER_IMAGE_ID || !/^sha256:[a-f0-9]{64}$/.test(record.imageId)) {
    throw Error('Unrecorded browser image');
  }
  const base = '/candidate/ansible/playbooks/keycloak/tests/browser/';
  phase = 'metadata';
  for (const [built, source] of [['/proof/package.json', 'package.json'], ['/proof/package-lock.json', 'package-lock.json'],
      ['/usr/share/doc/cloudlab-browser/Dockerfile', 'Dockerfile']]) {
    if (!fs.readFileSync(built).equals(fs.readFileSync(base + source))) throw Error('Stale browser build');
  }
  const version = JSON.parse(fs.readFileSync('/proof/package.json')).dependencies.playwright;
  phase = 'packages';
  for (const name of ['playwright', 'playwright-core']) {
    if (JSON.parse(fs.readFileSync('/proof/node_modules/' + name + '/package.json')).version !== version) {
      throw Error('Browser package version differs');
    }
  }
  const executable = require('/proof/node_modules/playwright').chromium.executablePath();
  phase = 'browser';
  const native = spawnSync(executable, ['--version'], {encoding: 'utf8', timeout: 30000});
  if (native.status !== 0 || !/^(?:Chromium|Google Chrome for Testing) [0-9.]+\s*$/.test(native.stdout)) throw Error('Browser binary check failed');
  const functional = spawnSync(process.execPath, ['-e',
    "const{chromium}=require('/proof/node_modules/playwright');(async()=>{const browser=await chromium.launch({headless:true,args:['--no-sandbox']});try{const page=await browser.newPage();await page.setContent('<title>CloudLab browser proof</title>');if(await page.title()!=='CloudLab browser proof')throw Error('title')}finally{await browser.close()}})().catch(()=>process.exit(1))"],
    {encoding: 'utf8', timeout: 60000, maxBuffer: 65536, env: {...process.env, HOME: '/tmp/home'}});
  if (functional.status !== 0) throw Error('Browser functional check failed');
  phase = 'result';
  fs.writeFileSync('/results/browser.json', JSON.stringify({...record, version, passed: true}));
  process.stdout.write(JSON.stringify({passed: true, version, nativeBrowserChecked: true}) + '\n');
} catch {
  process.stderr.write(JSON.stringify({passed: false, stage: phase}) + '\n');
  process.exitCode = 1;
}
