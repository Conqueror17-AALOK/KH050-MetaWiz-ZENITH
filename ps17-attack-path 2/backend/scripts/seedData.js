/**
 * Synthetic org generator for PS17.
 * Builds a fake company's identity/asset graph and loads it into Neo4j:
 *   - Users, groups, service accounts, machines, a Domain Admin group
 *   - Randomized "normal" relationships (group memberships, RDP access, sessions)
 *   - 2 deliberately planted multi-hop attack paths to Domain Admin, so the
 *     demo always has a guaranteed non-obvious path to discover.
 *
 * Run with: npm run seed
 */
require('dotenv').config();
const { driver, verifyConnection, closeDriver } = require('../config/db');
const { RELATIONSHIP_TYPES: R } = require('../config/relationshipTypes');

const NUM_USERS = 40;
const NUM_MACHINES = 12;
const NUM_SERVICE_ACCOUNTS = 6;
const NUM_GROUPS = 5;

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

async function seed() {
  await verifyConnection();
  const session = driver.session();

  try {
    console.log('Clearing existing graph...');
    await session.run('MATCH (n) DETACH DELETE n');

    const nodes = [];

    // Domain Admin group - the target
    nodes.push({ id: 'grp-domain-admins', type: 'Group', name: 'Domain Admins', critical: true });

    // Regular groups
    const groupIds = [];
    for (let i = 0; i < NUM_GROUPS; i++) {
      const id = `grp-${i}`;
      groupIds.push(id);
      nodes.push({ id, type: 'Group', name: `Group-${i}`, critical: false });
    }

    // Users
    const userIds = [];
    for (let i = 0; i < NUM_USERS; i++) {
      const id = `user-${i}`;
      userIds.push(id);
      nodes.push({ id, type: 'User', name: `user${i}`, critical: false });
    }

    // Service accounts
    const svcIds = [];
    for (let i = 0; i < NUM_SERVICE_ACCOUNTS; i++) {
      const id = `svc-${i}`;
      svcIds.push(id);
      nodes.push({ id, type: 'ServiceAccount', name: `svc-account-${i}`, critical: false });
    }

    // Machines
    const machineIds = [];
    for (let i = 0; i < NUM_MACHINES; i++) {
      const id = `machine-${i}`;
      machineIds.push(id);
      nodes.push({ id, type: 'Machine', name: `HOST-${i}`, critical: i === 0 }); // machine-0 = domain controller
    }

    console.log(`Creating ${nodes.length} nodes...`);
    await session.run(
      `UNWIND $nodes AS n
       CREATE (x {id: n.id})
       SET x.name = n.name, x.critical = n.critical
       WITH x, n
       CALL apoc.create.addLabels(x, [n.type]) YIELD node
       RETURN count(node)`,
      { nodes }
    ).catch(async () => {
      // Fallback if APOC isn't installed on the instance (e.g. some Aura Free setups):
      // create labeled nodes per type in separate batches instead.
      const byType = nodes.reduce((acc, n) => {
        (acc[n.type] ||= []).push(n);
        return acc;
      }, {});
      for (const [type, group] of Object.entries(byType)) {
        await session.run(
          `UNWIND $nodes AS n CREATE (x:${type} {id: n.id, name: n.name, critical: n.critical})`,
          { nodes: group }
        );
      }
    });

    const edges = [];

    // Random "normal" relationships
    for (const uid of userIds) {
      // Most users belong to 1-2 regular groups
      edges.push({ from: uid, to: pick(groupIds), type: R.MEMBER_OF.label });
      if (Math.random() < 0.3) edges.push({ from: uid, to: pick(groupIds), type: R.MEMBER_OF.label });

      // Some users can RDP into some machines
      if (Math.random() < 0.4) {
        edges.push({ from: uid, to: pick(machineIds), type: R.CAN_RDP.label });
      }
      // Some users have cached sessions on machines they've logged into
      if (Math.random() < 0.25) {
        edges.push({ from: uid, to: pick(machineIds), type: R.HAS_SESSION.label });
      }
    }

    // Service accounts often run with elevated rights on specific machines
    for (const sid of svcIds) {
      edges.push({ from: sid, to: pick(machineIds), type: R.ADMIN_TO.label });
      if (Math.random() < 0.3) {
        edges.push({ from: sid, to: pick(machineIds), type: R.HAS_SESSION.label });
      }
    }

    // A couple of machines trust the domain controller (machine-0)
    for (const mid of machineIds) {
      if (Math.random() < 0.15 && mid !== 'machine-0') {
        edges.push({ from: mid, to: 'machine-0', type: R.TRUSTED_BY.label });
      }
    }

    // --- Planted attack path #1 (4 hops) ---
    // A low-priv user -> RDP into a machine -> that machine has a cached
    // session of a service account -> that service account can reset the
    // password of a Domain Admins group member -> effectively Domain Admin.
    const plantedUser1 = userIds[3];
    const plantedMachine1 = 'machine-5';
    const plantedSvc1 = svcIds[0];
    edges.push({ from: plantedUser1, to: plantedMachine1, type: R.CAN_RDP.label });
    edges.push({ from: plantedMachine1, to: plantedSvc1, type: R.HAS_SESSION.label });
    edges.push({ from: plantedSvc1, to: 'grp-domain-admins', type: R.CAN_RESET_PASSWORD_OF.label });

    // --- Planted attack path #2 (5 hops, different technique: DCOM + trust) ---
    const plantedUser2 = userIds[17];
    const plantedMachine2a = 'machine-8';
    const plantedMachine2b = 'machine-2';
    edges.push({ from: plantedUser2, to: plantedMachine2a, type: R.EXECUTE_DCOM.label });
    edges.push({ from: plantedMachine2a, to: plantedMachine2b, type: R.TRUSTED_BY.label });
    edges.push({ from: plantedMachine2b, to: svcIds[1], type: R.HAS_SESSION.label });
    edges.push({ from: svcIds[1], to: 'grp-domain-admins', type: R.ADMIN_TO.label });

    console.log(`Creating ${edges.length} relationships...`);
    for (const [type, weight] of Object.entries(R).map(([, v]) => [v.label, v.weight])) {
      const batch = edges.filter((e) => e.type === type);
      if (!batch.length) continue;
      await session.run(
        `UNWIND $edges AS e
         MATCH (a {id: e.from}), (b {id: e.to})
         CALL apoc.create.relationship(a, e.type, {weight: $weight}, b) YIELD rel
         RETURN count(rel)`,
        { edges: batch, weight }
      ).catch(async () => {
        // Fallback without APOC: one Cypher statement per relationship type
        await session.run(
          `UNWIND $edges AS e
           MATCH (a {id: e.from}), (b {id: e.to})
           CREATE (a)-[r:${type} {weight: $weight}]->(b)`,
          { edges: batch, weight }
        );
      });
    }

    console.log('Seed complete.');
    console.log(`Planted path 1: ${plantedUser1} -> ${plantedMachine1} -> ${plantedSvc1} -> grp-domain-admins`);
    console.log(`Planted path 2: ${plantedUser2} -> ${plantedMachine2a} -> ${plantedMachine2b} -> ${svcIds[1]} -> grp-domain-admins`);
  } finally {
    await session.close();
    await closeDriver();
  }
}

seed().catch((err) => {
  console.error(err);
  process.exit(1);
});
