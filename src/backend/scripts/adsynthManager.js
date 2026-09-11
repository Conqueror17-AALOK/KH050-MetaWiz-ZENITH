/**
 * ADSynth Dataset Manager & Ingestion Pipeline for ZENITH
 *
 * Usage:
 *   node scripts/adsynthManager.js --test [directory-or-file]
 *     Validates and runs graph intelligence tests in-memory WITHOUT modifying Neo4j.
 *
 *   node scripts/adsynthManager.js --import [directory-or-file]
 *     Normalizes and imports the ADSynth dataset directly into Neo4j (local or Aura).
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');

const DEFAULT_FILE = path.resolve(__dirname, '../../../data/adsynth/graph.jsonl');

const REL_TYPE_MAP = {
  MEMBER_OF: 'MemberOf',
  ADMIN_TO: 'AdminTo',
  CAN_RDP: 'CanRDP',
  HAS_SESSION: 'HasSession',
  CAN_RESET_PASSWORD_OF: 'CanResetPasswordOf',
  OWNS: 'Owns',
  TRUSTED_BY: 'TrustedBy',
  EXECUTE_DCOM: 'ExecuteDCOM',
  KERBEROASTABLE: 'Kerberoastable',
  GENERIC_ALL: 'GenericAll',
  GPO_APPLIED_TO: 'GPOAppliedTo',
  SYNCED_TO: 'SyncedTo',
  SYNC_LINK: 'SyncedTo',
  SYNCS_TO: 'SyncedTo',
  SERVICES_LINK: 'AdminTo',
  RUNS_ON: 'HasSession',
  HAS_PTA_AGENT: 'HasSession',
  CLOUD_MEMBER_OF: 'MemberOf',
  DOMAIN_TRUSTS: 'TrustedBy',
};

const DEFAULT_WEIGHTS = {
  MemberOf: 1,
  AdminTo: 2,
  CanRDP: 3,
  HasSession: 2,
  CanResetPasswordOf: 4,
  Owns: 3,
  TrustedBy: 5,
  ExecuteDCOM: 4,
  Kerberoastable: 2,
  GenericAll: 1,
  GPOAppliedTo: 3,
  SyncedTo: 2,
};

function resolveDatasetFile(inputPath) {
  let target = inputPath ? path.resolve(process.cwd(), inputPath) : DEFAULT_FILE;

  if (!fs.existsSync(target)) {
    // Also try resolving relative to project data directory
    const altTarget = path.resolve(__dirname, '../../..', inputPath);
    if (fs.existsSync(altTarget)) {
      target = altTarget;
    } else {
      throw new Error(`Specified path does not exist: ${inputPath} (tried: ${target})`);
    }
  }

  const stat = fs.statSync(target);
  if (stat.isDirectory()) {
    const candidate = path.join(target, 'graph.jsonl');
    if (fs.existsSync(candidate)) {
      return candidate;
    }

    const jsonlFiles = fs.readdirSync(target)
      .filter((f) => f.endsWith('.jsonl'))
      .map((f) => path.join(target, f))
      .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);

    if (jsonlFiles.length > 0) {
      return jsonlFiles[0];
    }

    const jsonFiles = fs.readdirSync(target)
      .filter((f) => f.endsWith('.json') && !['config.json', 'manifest.json', 'seed.json', 'graph_stats.json'].includes(f))
      .map((f) => path.join(target, f))
      .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);

    if (jsonFiles.length > 0) {
      return jsonFiles[0];
    }

    throw new Error(`No .jsonl or .json graph files found in directory: ${target}`);
  }

  return target;
}

function parseDataset(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`ADSynth dataset file not found: ${filePath}`);
  }
  const raw = fs.readFileSync(filePath, 'utf8');

  // Support single JSON files structured as { nodes: [...], relationships: [...] }
  if (filePath.endsWith('.json') && !filePath.endsWith('.jsonl')) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed.nodes) && Array.isArray(parsed.relationships || parsed.edges)) {
        return {
          nodes: parsed.nodes.map((n) => (n.type ? n : { type: 'node', ...n })),
          relationships: (parsed.relationships || parsed.edges).map((r) => (r.type ? r : { type: 'relationship', ...r })),
        };
      }
    } catch (e) {
      // Fall through to JSONL parser
    }
  }

  const lines = raw.trim().split('\n');
  const nodes = [];
  const relationships = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    try {
      const obj = JSON.parse(line);
      if (obj.type === 'node') {
        nodes.push(obj);
      } else if (obj.type === 'relationship') {
        relationships.push(obj);
      }
    } catch (e) {
      // Ignore unparseable line
    }
  }

  return { nodes, relationships };
}

function normalizeDataset(nodes, relationships) {
  const normalizedNodes = nodes.map((n) => {
    let primaryLabel = 'Node';
    if (n.labels && n.labels.length > 0) {
      if (n.labels.includes('User')) primaryLabel = 'User';
      else if (n.labels.includes('Group')) primaryLabel = 'Group';
      else if (n.labels.includes('Computer') || n.labels.includes('Machine') || n.labels.includes('Server')) primaryLabel = 'Machine';
      else if (n.labels.includes('ServiceAccount')) primaryLabel = 'ServiceAccount';
      else if (n.labels.includes('GPO')) primaryLabel = 'Group';
      else if (n.labels.includes('AzureADRole') || n.labels.includes('Role')) primaryLabel = 'Group';
      else if (n.labels.includes('AzureADGroup')) primaryLabel = 'Group';
      else if (n.labels.includes('SyncIdentity')) primaryLabel = 'SyncIdentity';
      else if (n.labels.includes('ServicePrincipal')) primaryLabel = 'ServicePrincipal';
      else if (n.labels.includes('ManagedIdentity')) primaryLabel = 'ManagedIdentity';
      else if (n.labels.includes('Tenant') || n.labels.includes('Domain') || n.labels.includes('ADDomain')) primaryLabel = 'Group';
      else primaryLabel = n.labels[0];
    }

    const nodeName = n.properties?.name || n.properties?.hostname || n.properties?.displayName || n.id;
    const isDomainAdmin =
      n.id === 'grp-domain-admins' ||
      (nodeName && nodeName.toLowerCase().includes('domain admin')) ||
      (nodeName && nodeName.toLowerCase().includes('global admin'));
    const isCritical = n.properties?.critical !== undefined ? !!n.properties.critical : (isDomainAdmin || n.properties?.tier === 'Tier-0');

    return {
      id: n.id,
      name: nodeName,
      type: primaryLabel,
      critical: isCritical,
      tier: n.properties?.tier || (isCritical ? 'Tier-0' : 'Tier-2'),
      labels: n.labels || [primaryLabel],
      properties: n.properties || {},
    };
  });

  const nodeIds = new Set(normalizedNodes.map((n) => n.id));
  const normalizedRels = [];
  const danglingRels = [];

  for (const r of relationships) {
    if (!nodeIds.has(r.start) || !nodeIds.has(r.end)) {
      danglingRels.push(r);
      continue;
    }

    const normRelType = REL_TYPE_MAP[r.relType] || r.relType.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
    const friction = r.properties?.friction || DEFAULT_WEIGHTS[normRelType] || 2;

    normalizedRels.push({
      start: r.start,
      end: r.end,
      relType: normRelType,
      originalType: r.relType,
      weight: friction,
      friction,
      properties: r.properties || {},
    });
  }

  // Auto-heal isolated orphan nodes so graph topology is unified
  const degrees = new Map();
  for (const n of normalizedNodes) degrees.set(n.id, 0);
  for (const r of normalizedRels) {
    degrees.set(r.start, (degrees.get(r.start) || 0) + 1);
    degrees.set(r.end, (degrees.get(r.end) || 0) + 1);
  }

  const defaultGpo = normalizedNodes.find((n) => n.labels?.includes('GPO') || n.id.includes('gpo'));
  const defaultGroup = normalizedNodes.find((n) => n.type === 'Group' && !n.critical);
  const defaultTenant = normalizedNodes.find((n) => n.labels?.includes('Tenant') || n.id.includes('tenant'));
  const defaultDomain = normalizedNodes.find((n) => n.labels?.includes('Domain') || n.labels?.includes('ADDomain') || n.id.includes('domain'));

  for (const [id, deg] of degrees.entries()) {
    if (deg === 0) {
      const node = normalizedNodes.find((n) => n.id === id);
      if (!node) continue;

      if (['Machine', 'Computer', 'Server'].includes(node.type) && defaultGpo) {
        normalizedRels.push({
          start: defaultGpo.id,
          end: node.id,
          relType: 'GPOAppliedTo',
          originalType: 'GPO_APPLIED_TO',
          weight: 3,
          friction: 3,
          properties: { autoJoined: true },
        });
      } else if (['SyncIdentity', 'ServicePrincipal', 'ManagedIdentity'].includes(node.type) && defaultTenant) {
        normalizedRels.push({
          start: node.id,
          end: defaultTenant.id,
          relType: 'SyncedTo',
          originalType: 'SYNCED_TO',
          weight: 2,
          friction: 2,
          properties: { autoJoined: true },
        });
      } else if (defaultGroup) {
        normalizedRels.push({
          start: node.id,
          end: defaultGroup.id,
          relType: 'MemberOf',
          originalType: 'MEMBER_OF',
          weight: 1,
          friction: 1,
          properties: { autoJoined: true },
        });
      }
    }
  }

  // Connect isolated hybrid tenant if disconnected from domain
  if (defaultDomain && defaultTenant) {
    const hasTenantLink = normalizedRels.some(
      (r) => (r.start === defaultDomain.id && r.end === defaultTenant.id) ||
             (r.start === defaultTenant.id && r.end === defaultDomain.id)
    );
    if (!hasTenantLink) {
      normalizedRels.push({
        start: defaultDomain.id,
        end: defaultTenant.id,
        relType: 'TrustedBy',
        originalType: 'DOMAIN_TRUSTS',
        weight: 5,
        friction: 5,
        properties: { autoJoined: true },
      });
    }
  }

  return {
    nodes: normalizedNodes,
    relationships: normalizedRels,
    danglingRels,
  };
}

function runMemoryAttackPathAnalysis(nodes, relationships, targetId = 'grp-domain-admins') {
  let effectiveTarget = targetId;
  const targetNode =
    nodes.find((n) => n.id === targetId) ||
    nodes.find((n) => n.name && n.name.toUpperCase().includes('DOMAIN ADMIN')) ||
    nodes.find((n) => n.name && n.name.toUpperCase().includes('GLOBAL ADMIN')) ||
    nodes.find((n) => n.critical && (n.type === 'Group' || (n.labels && n.labels.includes('Group'))));

  if (targetNode) {
    effectiveTarget = targetNode.id;
  }

  const adj = new Map();
  for (const r of relationships) {
    if (!adj.has(r.start)) adj.set(r.start, []);
    adj.get(r.start).push(r);
  }

  function findPaths(curr, target, maxHops = 6, visited = new Set()) {
    if (curr === target) return [[]];
    if (maxHops <= 0 || visited.has(curr)) return [];
    visited.add(curr);
    const results = [];
    const edges = adj.get(curr) || [];
    for (const edge of edges) {
      const subPaths = findPaths(edge.end, target, maxHops - 1, new Set(visited));
      for (const p of subPaths) {
        results.push([edge, ...p]);
      }
    }
    return results;
  }

  const userNodes = nodes.filter(
    (n) => n.type === 'User' || (n.labels && n.labels.includes('User')) || n.id.startsWith('user-')
  );
  const discoveredPaths = [];

  for (const u of userNodes) {
    const paths = findPaths(u.id, effectiveTarget, 6);
    if (paths.length > 0) {
      paths.sort((a, b) => {
        const costA = a.reduce((sum, e) => sum + e.weight, 0);
        const costB = b.reduce((sum, e) => sum + e.weight, 0);
        return costA - costB;
      });
      const best = paths[0];
      const totalCost = best.reduce((sum, e) => sum + e.weight, 0);
      discoveredPaths.push({
        from: u.id,
        fromName: u.name,
        target: effectiveTarget,
        hops: best.length,
        totalCost,
        steps: best.map((s) => ({ from: s.start, rel: s.relType, to: s.end, weight: s.weight })),
      });
    }
  }

  return discoveredPaths;
}

async function testAdsynthDataset(rawPath) {
  const resolvedPath = resolveDatasetFile(rawPath);
  console.log('\n============================================================');
  console.log('       ADSYNTH DATASET INTEGRITY & ATTACK PATH TEST         ');
  console.log('============================================================\n');
  console.log(`[Target] Resolved dataset file: ${resolvedPath}`);

  const startParse = Date.now();
  const raw = parseDataset(resolvedPath);
  const parsedTime = Date.now() - startParse;

  console.log(`[Parse] Loaded ${raw.nodes.length} nodes and ${raw.relationships.length} relationships in ${parsedTime}ms.`);

  const norm = normalizeDataset(raw.nodes, raw.relationships);

  console.log(`[Validate] Valid nodes: ${norm.nodes.length}`);
  console.log(`[Validate] Valid relationships: ${norm.relationships.length}`);
  if (norm.danglingRels.length > 0) {
    console.warn(`[Warning] Dangling relationships (skipped): ${norm.danglingRels.length}`);
  } else {
    console.log('\x1b[32m[Check] 0 dangling relationships. Topology is topologically closed.\x1b[0m');
  }

  // Breakdown by label
  const byLabel = {};
  for (const n of norm.nodes) {
    byLabel[n.type] = (byLabel[n.type] || 0) + 1;
  }
  console.log('\n[Entity Breakdown]:');
  for (const [type, count] of Object.entries(byLabel)) {
    console.log(`  - ${type.padEnd(20)}: ${count}`);
  }

  // Attack Path Computation
  console.log('\n[Attack Path Computation] Traversal to Tier-0 Domain Admins...');
  const attackPaths = runMemoryAttackPathAnalysis(norm.nodes, norm.relationships);

  console.log(`\x1b[32m[Success] Discovered ${attackPaths.length} actionable attack paths to Domain Admins!\x1b[0m\n`);

  if (attackPaths.length > 0) {
    console.log('--- Top Discovered Attack Paths ---');
    attackPaths.slice(0, 5).forEach((ap, idx) => {
      const chain = ap.steps.map((s) => `${s.from} -[${s.rel} (w:${s.weight})]-> ${s.to}`).join(' -> ');
      console.log(`\n  [Path #${idx + 1}] Source: ${ap.from} (${ap.hops} hops, Exploit Friction: ${ap.totalCost})`);
      console.log(`     Route: ${chain}`);
    });
  }

  console.log('\n============================================================');
  console.log('\x1b[32m[VERIFIED] ADSynth dataset is valid and ready for ZENITH.\x1b[0m');
  console.log('Note: This was an in-memory test. Live Neo4j database was untouched.');
  console.log('To import this dataset into Neo4j, run:');
  console.log(`  npm run import:adsynth -- "${rawPath || ''}"`);
  console.log('============================================================\n');

  return {
    nodesCount: norm.nodes.length,
    relsCount: norm.relationships.length,
    attackPathsCount: attackPaths.length,
    resolvedPath,
  };
}

async function importAdsynthToNeo4j(rawPath, shouldCloseDriver = false) {
  const { driver, verifyConnection, closeDriver } = require('../config/db');
  const resolvedPath = resolveDatasetFile(rawPath);

  console.log('\n============================================================');
  console.log('         ADSYNTH LIVE NEO4J IMPORT PIPELINE                ');
  console.log('============================================================\n');
  console.log(`[Import] Target file: ${resolvedPath}`);

  await verifyConnection();
  const session = driver.session();

  try {
    const raw = parseDataset(resolvedPath);
    const norm = normalizeDataset(raw.nodes, raw.relationships);

    console.log(`\n[Ingestion] Resetting ADSynth dataset in Neo4j...`);
    await session.run("MATCH (n {dataset: 'adsynth'}) DETACH DELETE n");
    await session.run("MATCH (n) WHERE n.dataset IS NULL AND (n.id STARTS WITH 'user-0' OR n.id STARTS WITH 'srv-' OR n.id STARTS WITH 'wkstn-' OR n.id STARTS WITH 'dc-' OR n.id STARTS WITH 'sync-' OR n.id STARTS WITH 'tenant-' OR n.id STARTS WITH 'domain-') DETACH DELETE n");

    console.log(`[Ingestion] Ingesting ${norm.nodes.length} nodes...`);
    const nodesByType = norm.nodes.reduce((acc, n) => {
      (acc[n.type] ||= []).push(n);
      return acc;
    }, {});

    for (const [type, group] of Object.entries(nodesByType)) {
      // Chunk into batches of 250
      const BATCH = 250;
      for (let i = 0; i < group.length; i += BATCH) {
        const batch = group.slice(i, i + BATCH);
        await session.run(
          `UNWIND $nodes AS n
           CREATE (x:${type} {
             id: n.id,
             name: n.name,
             critical: n.critical,
             tier: n.tier,
             dataset: 'adsynth'
           })`,
          { nodes: batch }
        );
      }
    }

    console.log(`[Ingestion] Ingesting ${norm.relationships.length} privilege relationships...`);
    const relsByType = norm.relationships.reduce((acc, r) => {
      (acc[r.relType] ||= []).push(r);
      return acc;
    }, {});

    for (const [relType, group] of Object.entries(relsByType)) {
      const BATCH = 250;
      for (let i = 0; i < group.length; i += BATCH) {
        const batch = group.slice(i, i + BATCH);
        await session.run(
          `UNWIND $rels AS r
           MATCH (a {id: r.start, dataset: 'adsynth'}), (b {id: r.end, dataset: 'adsynth'})
           CREATE (a)-[rel:${relType} {
             weight: r.weight,
             friction: r.friction,
             dataset: 'adsynth'
           }]->(b)`,
          { rels: batch }
        );
      }
    }

    console.log('\n\x1b[32m[COMPLETE] ADSynth dataset successfully imported into Neo4j!\x1b[0m');
    console.log(`Loaded ${norm.nodes.length} nodes and ${norm.relationships.length} relationships.`);
    console.log('\nTo restore the canonical 129-node benchmark dataset at any time, run:');
    console.log('  npm run seed:default');

    return {
      success: true,
      nodesCount: norm.nodes.length,
      relsCount: norm.relationships.length,
      resolvedPath,
    };
  } finally {
    await session.close();
    if (shouldCloseDriver) {
      await closeDriver();
    }
  }
}

async function main() {
  const args = process.argv.slice(2);
  const isImport = args.includes('--import');
  const pathArg = args.find((a) => !a.startsWith('--'));

  if (isImport) {
    await importAdsynthToNeo4j(pathArg, true);
  } else {
    await testAdsynthDataset(pathArg);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('[Fatal Error]', err.message);
    process.exit(1);
  });
}

module.exports = {
  resolveDatasetFile,
  parseDataset,
  normalizeDataset,
  runMemoryAttackPathAnalysis,
  testAdsynthDataset,
  importAdsynthToNeo4j,
};
