/**
 * ZENITH System Diagnostics & Test Suite
 * Validates all API endpoints, Cypher algorithms, error boundaries, and latency.
 */

const http = require('http');

const BASE_URL = 'http://localhost:4000/api';

function request(path, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(`${BASE_URL}${path}`);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method,
      headers: {
        'Content-Type': 'application/json',
      },
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve({ status: res.statusCode, data: parsed });
        } catch (e) {
          resolve({ status: res.statusCode, data });
        }
      });
    });

    req.on('error', reject);

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

async function runDiagnostics() {
  console.log('====================================================');
  console.log('       ZENITH SYSTEM DIAGNOSTIC TEST SUITE          ');
  console.log('====================================================\n');

  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    process.stdout.write(`[TEST] ${name.padEnd(52)} `);
    const start = Date.now();
    try {
      await fn();
      const elapsed = Date.now() - start;
      console.log(`\x1b[32mPASSED\x1b[0m (${elapsed}ms)`);
      passed++;
    } catch (err) {
      console.log(`\x1b[31mFAILED\x1b[0m: ${err.message}`);
      failed++;
    }
  }

  // 1. Relationship Types
  await test('GET /api/relationship-types (Taxonomy check)', async () => {
    const res = await request('/relationship-types');
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    const types = Object.keys(res.data);
    if (!types.includes('KERBEROASTABLE') || !types.includes('GENERIC_ALL') || !types.includes('GPO_APPLIED_TO')) {
      throw new Error('Missing Phase 2 relationship types');
    }
  });

  // 2. Full Graph Payload
  let graphData;
  await test('GET /api/graph (Full topology payload)', async () => {
    const res = await request('/graph');
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    graphData = res.data;
    if (graphData.nodes.length < 100) throw new Error(`Expected >=100 nodes, got ${graphData.nodes.length}`);
    if (graphData.links.length < 150) throw new Error(`Expected >=150 links, got ${graphData.links.length}`);
  });

  // 3. Planted Path 1 (user-3)
  let path1;
  await test('GET /api/paths (Planted Path 1: RDP session hijack)', async () => {
    const res = await request('/paths?from=user-3&to=grp-domain-admins');
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (!res.data.paths || res.data.paths.length === 0) throw new Error('No paths found');
    path1 = res.data.paths[0];
    if (path1.hops !== 3) throw new Error(`Expected 3 hops, got ${path1.hops}`);
    if (path1.riskScore < 50) throw new Error(`Expected risk >= 50, got ${path1.riskScore}`);
  });

  // 4. Planted Path 2 (user-17)
  await test('GET /api/paths (Planted Path 2: DCOM host trust)', async () => {
    const res = await request('/paths?from=user-17&to=grp-domain-admins');
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (!res.data.paths || res.data.paths.length === 0) throw new Error('No paths found');
    const p = res.data.paths[0];
    if (p.hops < 3 || p.hops > 5) throw new Error(`Unexpected hop count: ${p.hops}`);
  });

  // 5. Planted Path 3 (user-42) - GPO & GenericAll
  await test('GET /api/paths (Planted Path 3: GPO ACL abuse)', async () => {
    const res = await request('/paths?from=user-42&to=grp-domain-admins');
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (!res.data.paths || res.data.paths.length === 0) throw new Error('No paths found');
    const p = res.data.paths[0];
    const rels = p.steps.map((s) => s.relationship);
    if (!rels.includes('GenericAll') && !rels.includes('GPOAppliedTo')) {
      throw new Error('Path does not utilize GPO/GenericAll techniques');
    }
  });

  // 6. Planted Path 4 (user-29) - Kerberoasting
  await test('GET /api/paths (Planted Path 4: Kerberoasting)', async () => {
    const res = await request('/paths?from=user-29&to=grp-domain-admins');
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (!res.data.paths || res.data.paths.length === 0) throw new Error('No paths found');
    const p = res.data.paths[0];
    const rels = p.steps.map((s) => s.relationship);
    if (!rels.includes('Kerberoastable')) {
      throw new Error('Path does not utilize Kerberoastable relationship');
    }
  });

  // 7. Non-existent identity boundary test
  await test('GET /api/paths (Non-existent identity boundary check)', async () => {
    const res = await request('/paths?from=non-existent-user-999&to=grp-domain-admins');
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (res.data.paths.length !== 0) throw new Error('Expected 0 paths for fake user');
  });

  // 8. Blast Radius
  await test('GET /api/blast-radius/:id (Reachable cascade check)', async () => {
    const res = await request('/blast-radius/user-3');
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (res.data.reachableCount < 3) throw new Error(`Expected >=3 reachable, got ${res.data.reachableCount}`);
    const criticals = res.data.reachable.filter((n) => n.critical);
    if (criticals.length === 0) throw new Error('Expected at least 1 critical node reachable in blast radius');
  });

  // 9. Remediation Simulation: Chokepoint Severed
  await test('POST /api/simulate-remediation (Chokepoint elimination)', async () => {
    const chokepointStep = path1.steps[1]; // HasSession from SRV-5 to svc-0
    const res = await request('/simulate-remediation', 'POST', {
      from: 'user-3',
      to: 'grp-domain-admins',
      excludeRelId: chokepointStep.relId,
    });
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (!res.data.pathEliminated) throw new Error('Expected pathEliminated to be true');
    if (res.data.remainingPathCount !== 0) throw new Error('Expected remainingPathCount to be 0');
  });

  // 10. Remediation Simulation: Path Rerouting
  await test('POST /api/simulate-remediation (Alternate route rerouting)', async () => {
    // Exclude first non-fatal edge in user-42 path
    const res = await request('/paths?from=user-42&to=grp-domain-admins');
    const p3 = res.data.paths[0];
    const nonFatalRelId = p3.steps[1].relId;
    const remRes = await request('/simulate-remediation', 'POST', {
      from: 'user-42',
      to: 'grp-domain-admins',
      excludeRelId: nonFatalRelId,
    });
    if (remRes.status !== 200) throw new Error(`HTTP ${remRes.status}`);
    // Path might reroute or eliminate
    if (remRes.data.pathEliminated && remRes.data.reRoutedPath) {
      throw new Error('Inconsistent rerouting response payload');
    }
  });

  // 11. Decoupled LLM Threat Briefing
  await test('POST /api/explain-path (MITRE ATT&CK Threat Briefing)', async () => {
    const res = await request('/explain-path', 'POST', {
      from: 'user-3',
      to: 'grp-domain-admins',
      path: path1,
    });
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (!res.data.executiveSummary) throw new Error('Missing executiveSummary');
    if (!res.data.mitreTechniques || res.data.mitreTechniques.length === 0) throw new Error('Missing MITRE techniques');
    if (!res.data.remediationPlaybook || res.data.remediationPlaybook.length === 0) throw new Error('Missing remediation playbook');
  });

  // 12. Live Judge Scenario Injection
  await test('POST /api/inject (Live relationship insertion into Neo4j)', async () => {
    const res = await request('/inject', 'POST', {
      from: 'user-60',
      to: 'machine-5',
      relationshipType: 'CanRDP',
    });
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (!res.data.success) throw new Error('Injection was not marked successful');
    if (res.data.type !== 'CanRDP') throw new Error(`Expected CanRDP, got ${res.data.type}`);
  });

  console.log('\n====================================================');
  console.log(`TOTAL: ${passed + failed} | PASSED: \x1b[32m${passed}\x1b[0m | FAILED: \x1b[31m${failed}\x1b[0m`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runDiagnostics().catch((err) => {
  console.error('Fatal diagnostic failure:', err);
  process.exit(1);
});
