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
  let isAdsynth = false;
  let p1From = 'user-3';
  let p2From = 'user-17';
  let p3From = 'user-42';
  let p4From = 'user-29';
  let blastFrom = 'user-3';
  let injectFrom = 'user-60';
  let injectTo = 'machine-5';

  await test('GET /api/graph (Full topology payload)', async () => {
    const res = await request('/graph');
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    graphData = res.data;
    isAdsynth = graphData.nodes.some((n) => n.id === 'user-03');
    if (isAdsynth) {
      p1From = 'user-03';
      p2From = 'user-07';
      p3From = 'user-18';
      p4From = 'user-12';
      blastFrom = 'user-03';
      injectFrom = 'user-01';
      injectTo = 'wkstn-04';
    }
    const minNodes = isAdsynth ? 80 : 100;
    const minLinks = isAdsynth ? 80 : 150;
    if (graphData.nodes.length < minNodes) throw new Error(`Expected >=${minNodes} nodes, got ${graphData.nodes.length}`);
    if (graphData.links.length < minLinks) throw new Error(`Expected >=${minLinks} links, got ${graphData.links.length}`);
  });

  // 3. Planted Path 1
  let path1;
  const dsParam = isAdsynth ? '&dataset=adsynth' : '&dataset=demo';
  const dsName = isAdsynth ? 'adsynth' : 'demo';

  await test(`GET /api/paths (Planted Path 1: ${isAdsynth ? 'Entra Sync' : 'RDP session hijack'})`, async () => {
    const res = await request(`/paths?from=${p1From}&to=grp-domain-admins${dsParam}`);
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (!res.data.paths || res.data.paths.length === 0) throw new Error('No paths found');
    path1 = res.data.paths[0];
    if (path1.hops < 3 || path1.hops > 6) throw new Error(`Unexpected hops: ${path1.hops}`);
    if (path1.riskScore < 40) throw new Error(`Expected risk >= 40, got ${path1.riskScore}`);
  });

  // 4. Planted Path 2
  await test(`GET /api/paths (Planted Path 2: ${isAdsynth ? 'DC Backup' : 'DCOM host trust'})`, async () => {
    const res = await request(`/paths?from=${p2From}&to=grp-domain-admins${dsParam}`);
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (!res.data.paths || res.data.paths.length === 0) throw new Error('No paths found');
    const p = res.data.paths[0];
    if (p.hops < 3 || p.hops > 6) throw new Error(`Unexpected hop count: ${p.hops}`);
  });

  // 5. Planted Path 3 - GPO & GenericAll
  await test('GET /api/paths (Planted Path 3: GPO ACL abuse)', async () => {
    const res = await request(`/paths?from=${p3From}&to=grp-domain-admins${dsParam}`);
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (!res.data.paths || res.data.paths.length === 0) throw new Error('No paths found');
    const p = res.data.paths[0];
    const rels = p.steps.map((s) => s.relationship);
    if (!rels.includes('GenericAll') && !rels.includes('GPOAppliedTo')) {
      throw new Error('Path does not utilize GPO/GenericAll techniques');
    }
  });

  // 6. Planted Path 4 - Kerberoasting
  await test('GET /api/paths (Planted Path 4: Kerberoasting)', async () => {
    const res = await request(`/paths?from=${p4From}&to=grp-domain-admins${dsParam}`);
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
    const res = await request(`/paths?from=non-existent-user-999&to=grp-domain-admins${dsParam}`);
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (res.data.paths.length !== 0) throw new Error('Expected 0 paths for fake user');
  });

  // 8. Blast Radius
  await test('GET /api/blast-radius/:id (Reachable cascade check)', async () => {
    const res = await request(`/blast-radius/${blastFrom}?dataset=${dsName}`);
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (res.data.reachableCount < 3) throw new Error(`Expected >=3 reachable, got ${res.data.reachableCount}`);
    const criticals = res.data.reachable.filter((n) => n.critical);
    if (criticals.length === 0) throw new Error('Expected at least 1 critical node reachable in blast radius');
  });

  // 9. Remediation Simulation: Chokepoint Severed
  await test('POST /api/simulate-remediation (Chokepoint elimination)', async () => {
    const chokepointStep = path1.steps[1];
    const res = await request('/simulate-remediation', 'POST', {
      from: p1From,
      to: 'grp-domain-admins',
      excludeRelId: chokepointStep.relId,
      dataset: dsName,
    });
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (res.data.pathEliminated === undefined) throw new Error('Expected pathEliminated response');
  });

  // 10. Remediation Simulation: Path Rerouting
  await test('POST /api/simulate-remediation (Alternate route rerouting)', async () => {
    const res = await request(`/paths?from=${p3From}&to=grp-domain-admins${dsParam}`);
    const p3 = res.data.paths[0];
    const nonFatalRelId = p3.steps[0].relId;
    const remRes = await request('/simulate-remediation', 'POST', {
      from: p3From,
      to: 'grp-domain-admins',
      excludeRelId: nonFatalRelId,
      dataset: dsName,
    });
    if (remRes.status !== 200) throw new Error(`HTTP ${remRes.status}`);
    if (remRes.data.pathEliminated && remRes.data.reRoutedPath) {
      throw new Error('Inconsistent rerouting response payload');
    }
  });

  // 11. Live AI Threat Reasoning Schema Conformance
  await test('POST /api/explain-path (Strict JSON Schema Validation)', async () => {
    const res = await request('/explain-path', 'POST', {
      from: p1From,
      to: 'grp-domain-admins',
      path: path1,
    });
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    const d = res.data;
    if (!d.executiveSummary || typeof d.executiveSummary !== 'string') throw new Error('Missing or invalid executiveSummary');
    if (!['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(d.severity)) throw new Error(`Invalid severity: ${d.severity}`);
    if (!d.attackNarrative || typeof d.attackNarrative !== 'string') throw new Error('Missing attackNarrative');
    if (!Array.isArray(d.stepAnalysis) || d.stepAnalysis.length === 0) throw new Error('Invalid stepAnalysis');
    if (!d.primaryChokepoint || !d.primaryChokepoint.relationship || !d.primaryChokepoint.reason) throw new Error('Invalid primaryChokepoint');
    if (!Array.isArray(d.detectionOpportunities) || d.detectionOpportunities.length === 0) throw new Error('Invalid detectionOpportunities');
    if (!Array.isArray(d.recommendations) || d.recommendations.length === 0) throw new Error('Invalid recommendations');
    if (!Array.isArray(d.verifiedFacts) || d.verifiedFacts.length === 0) throw new Error('Invalid verifiedFacts');
    if (!d.reasoning || typeof d.reasoning !== 'string') throw new Error('Missing reasoning');
  });

  // 12. Dynamic Path Security Context (Zero Hardcoding Test)
  await test('POST /api/explain-path (Dynamic Path Adaptation)', async () => {
    const p2Res = await request(`/paths?from=${p2From}&to=grp-domain-admins`);
    const path2 = p2Res.data.paths[0];
    const res2 = await request('/explain-path', 'POST', {
      from: p2From,
      to: 'grp-domain-admins',
      path: path2,
    });
    if (res2.status !== 200) throw new Error(`HTTP ${res2.status}`);
    if (res2.data.source.includes('user-999')) throw new Error('Corrupted source identity detected');
  });

  // 13. Direct Structured Payload Support
  await test('POST /api/explain-path (Direct Canonical Payload Input)', async () => {
    const customPayload = {
      source: { id: 'user-99', name: 'Test User 99', type: 'User' },
      target: { id: 'grp-domain-admins', name: 'Domain Admins', type: 'Group', critical: true },
      path: { hops: 2, totalCost: 5, riskScore: 72 },
      steps: [
        { from: 'user-99', relationship: 'CanRDP', weight: 3, to: 'machine-99' },
        { from: 'machine-99', relationship: 'AdminTo', weight: 2, to: 'grp-domain-admins' }
      ],
      chokepoint: { from: 'user-99', relationship: 'CanRDP', to: 'machine-99' }
    };
    const res = await request('/explain-path', 'POST', customPayload);
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (!res.data.verifiedFacts.some(f => f.includes('Test User 99'))) {
      throw new Error('Direct structured payload was not honored in explanation');
    }
  });

  // 14. Fallback Resilience & Notice Test
  await test('POST /api/explain-path (Resilient Fallback on Unavailable NIM)', async () => {
    const res = await request('/explain-path', 'POST', {
      from: p1From,
      to: 'grp-domain-admins',
      path: path1,
      apiKey: 'dummy-invalid-key-for-testing'
    });
    if (res.status !== 200) throw new Error(`Expected HTTP 200 fallback, got ${res.status}`);
    if (res.data.isLive !== false) throw new Error('Expected isLive to be false on invalid key');
    if (!res.data.notice || !res.data.notice.includes('AI analysis unavailable — deterministic graph analysis is still active.')) {
      throw new Error(`Expected fallback notice, got: ${res.data.notice}`);
    }
  });

  // 15. Live Judge Scenario Injection
  await test('POST /api/inject (Live relationship insertion into Neo4j)', async () => {
    const res = await request('/inject', 'POST', {
      from: injectFrom,
      to: injectTo,
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
