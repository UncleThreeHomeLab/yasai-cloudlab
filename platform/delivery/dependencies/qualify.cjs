// Public native qualification has no access to the token handoff or candidate code.
const fs = require('node:fs');
const {spawnSync} = require('node:child_process');
try {
  const record = JSON.parse(fs.readFileSync('/toolchain.json'));
  const pin = JSON.parse(fs.readFileSync('/candidate/platform/delivery/dependencies/image.lock.json'));
  const actual = JSON.parse(fs.readFileSync('/usr/local/renovate/package.json')).version;
  if (pin.image !== process.env.DEPENDENCY_RENOVATE_IMAGE || actual !== pin.version || record.role !== 'candidate-runner') {
    throw Error('Unqualified image identity');
  }
  for (const helper of ['validate.cjs', 'extract.cjs']) {
    const result = spawnSync(process.execPath, ['/trusted/' + helper], {
      encoding: 'utf8', timeout: 150000, maxBuffer: 1024 * 1024,
      env: {PATH: process.env.PATH, HOME: '/tmp/home'}
    });
    if (result.status !== 0 || JSON.parse(result.stdout.trim()).passed !== true) throw Error('Native qualification failed');
  }
  fs.writeFileSync('/results/renovate.json', JSON.stringify({operation: record.operation,
    candidateTree: record.candidateTree, image: pin.image, passed: true}));
  process.stdout.write(JSON.stringify({passed: true, nativeConfiguration: true, nativeExtraction: true}) + '\n');
} catch {
  process.stderr.write('Renovate native qualification failed; diagnostics withheld\n');
  process.exitCode = 1;
}
