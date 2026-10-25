const fs = require('node:fs');
const {spawnSync} = require('node:child_process');
const request = {repository: 'example/platform', base: 'main',
  ownerPaths: ['ansible/runner/tools.lock.json'], dependencies: ['opentofu/opentofu']};
fs.writeFileSync('/tmp/operation.json', JSON.stringify(request), {mode: 0o600});
const result = spawnSync('/usr/local/renovate/node', ['/usr/local/renovate/dist/config-validator.js', '--strict', '/trusted/renovate.cjs'], {
  encoding: 'utf8', timeout: 120000, maxBuffer: 1024 * 1024
});
if (result.status !== 0) {
  process.stderr.write(result.stdout + result.stderr);
  process.exitCode = 1;
} else {
  process.stdout.write(JSON.stringify({passed: true, configuration: 'trusted admin and exact owner selection'}) + '\n');
}
fs.rmSync('/tmp/operation.json', {force: true});
