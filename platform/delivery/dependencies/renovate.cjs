// Only the trusted operation request selects the exact repository and base.
const fs = require('node:fs');
const crypto = require('node:crypto');
const config = JSON.parse(fs.readFileSync('/trusted/renovate.json', 'utf8'));
const request = JSON.parse(fs.readFileSync('/tmp/operation.json', 'utf8'));
if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(request.repository) ||
    !/^(main|cloudlab-maintenance-fixture\/[a-z0-9-]{1,64})$/.test(request.base)) {
  throw new Error('Invalid maintenance repository scope');
}
config.repositories = [request.repository];
config.force.baseBranchPatterns = [request.base];
config.force.branchPrefix = 'cloudlab-maintenance/' + crypto.createHash('sha256').update(request.base).digest('hex').slice(0, 12) + '-';
config.force.includePaths = request.ownerPaths;
const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
config.force.packageRules.push({matchPackageNames: ['!/^(' + request.dependencies.map(escape).join('|') + ')$/'], enabled: false});
if (request.base.startsWith('cloudlab-maintenance-fixture/')) {
  config.force.packageRules.push({matchPackageNames: ['opentofu/opentofu'], allowedVersions: '=1.13.1'});
}
module.exports = config;
