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

const NUM_USERS = 75;
const NUM_MACHINES = 24;
const NUM_SERVICE_ACCOUNTS = 15;
const NUM_GROUPS = 12;

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

    // Domain Admin group - Tier-0 target
    nodes.push({ id: 'grp-domain-admins', type: 'Group', name: 'Domain Admins', critical: true });

    // Regular enterprise groups
    const groupNames = [
      'HelpDesk-Tier1', 'IT-Operations', 'Security-Operations', 'DevOps-Engineers',
      'Finance-Users', 'HR-Generalists', 'Database-Admins', 'Cloud-Engineers',
      'Workstation-Admins', 'Server-Operators', 'Contractors', 'Executive-Staff'
    ];
    const groupIds = [];
    for (let i = 0; i < NUM_GROUPS; i++) {
      const id = `grp-${i}`;
      groupIds.push(id);
      nodes.push({ id, type: 'Group', name: groupNames[i] || `Group-${i}`, critical: false });
    }

    // Enterprise Users
    const userIds = [];
    for (let i = 0; i < NUM_USERS; i++) {
      const id = `user-${i}`;
      userIds.push(id);
      nodes.push({ id, type: 'User', name: `user${i}`, critical: false });
    }

    // Service Accounts (sync, backups, SQL, deployment)
    const svcNames = [
      'svc-backup-operator', 'svc-entra-connect', 'svc-sql-cluster', 'svc-jenkins-agent',
      'svc-scanner', 'svc-monitoring', 'svc-ansible', 'svc-jira-sync', 'svc-gitlab-runner',
      'svc-file-indexer', 'svc-exchange-sync', 'svc-cert-enroll', 'svc-scom-agent',
      'svc-hyperv-replica', 'svc-adfs-proxy'
    ];
    const svcIds = [];
    for (let i = 0; i < NUM_SERVICE_ACCOUNTS; i++) {
      const id = `svc-${i}`;
      svcIds.push(id);
      nodes.push({ id, type: 'ServiceAccount', name: svcNames[i] || `svc-${i}`, critical: i === 0 });
    }

    // Machines (Domain Controllers, Servers, Workstations)
    const machineIds = [];
    for (let i = 0; i < NUM_MACHINES; i++) {
      const id = `machine-${i}`;
      machineIds.push(id);
      const isDC = i === 0 || i === 1;
      const name = isDC ? `DC-0${i + 1}.corp.local` : (i < 8 ? `SRV-${i}.corp.local` : `WKSTN-${i}.corp.local`);
      nodes.push({ id, type: 'Machine', name, critical: isDC });
    }

    // Group Policy Objects (GPOs)
    nodes.push({ id: 'gpo-workstation-policy', type: 'Group', name: 'GPO-Workstation-Lockdown', critical: false });
    nodes.push({ id: 'gpo-default-domain-policy', type: 'Group', name: 'GPO-Default-Domain-Policy', critical: true });

    console.log(`Creating ${nodes.length} nodes...`);
    // Create labeled nodes per type to guarantee consistent execution without APOC dependency
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

    const edges = [];

    // Random realistic enterprise relationships
    for (const uid of userIds) {
      // Users belong to 1-3 groups
      edges.push({ from: uid, to: pick(groupIds), type: R.MEMBER_OF.label });
      if (Math.random() < 0.4) edges.push({ from: uid, to: pick(groupIds), type: R.MEMBER_OF.label });

      // Interactive RDP access on workstations and some servers
      if (Math.random() < 0.35) {
        edges.push({ from: uid, to: pick(machineIds), type: R.CAN_RDP.label });
      }
      // Cached credential sessions on workstations
      if (Math.random() < 0.25) {
        edges.push({ from: uid, to: pick(machineIds), type: R.HAS_SESSION.label });
      }
    }

    // Service account permissions
    for (const sid of svcIds) {
      edges.push({ from: sid, to: pick(machineIds), type: R.ADMIN_TO.label });
      if (Math.random() < 0.35) {
        edges.push({ from: sid, to: pick(machineIds), type: R.HAS_SESSION.label });
      }
    }

    // Workstations and member servers trust Domain Controllers
    for (const mid of machineIds) {
      if (mid !== 'machine-0' && mid !== 'machine-1' && Math.random() < 0.2) {
        edges.push({ from: mid, to: 'machine-0', type: R.TRUSTED_BY.label });
      }
    }

    // GPO deployment to workstations
    for (let i = 8; i < NUM_MACHINES; i++) {
      if (Math.random() < 0.4) {
        edges.push({ from: 'gpo-workstation-policy', to: `machine-${i}`, type: R.GPO_APPLIED_TO.label });
      }
    }

    // --- Planted Attack Path #1 (3 hops): RDP -> LSASS Cached Session -> Password Reset ---
    const plantedUser1 = 'user-3';
    const plantedMachine1 = 'machine-5';
    const plantedSvc1 = 'svc-0';
    edges.push({ from: plantedUser1, to: plantedMachine1, type: R.CAN_RDP.label });
    edges.push({ from: plantedMachine1, to: plantedSvc1, type: R.HAS_SESSION.label });
    edges.push({ from: plantedSvc1, to: 'grp-domain-admins', type: R.CAN_RESET_PASSWORD_OF.label });

    // --- Planted Attack Path #2 (4 hops): DCOM RCE -> Host Trust -> Service Account Session -> Admin ---
    const plantedUser2 = 'user-17';
    const plantedMachine2a = 'machine-8';
    const plantedMachine2b = 'machine-2';
    const plantedSvc2 = 'svc-1';
    edges.push({ from: plantedUser2, to: plantedMachine2a, type: R.EXECUTE_DCOM.label });
    edges.push({ from: plantedMachine2a, to: plantedMachine2b, type: R.TRUSTED_BY.label });
    edges.push({ from: plantedMachine2b, to: plantedSvc2, type: R.HAS_SESSION.label });
    edges.push({ from: plantedSvc2, to: 'grp-domain-admins', type: R.ADMIN_TO.label });

    // --- Planted Attack Path #3 (4 hops): ACL GenericAll on GPO -> GPO Applied to Host -> Session -> Admin ---
    const plantedUser3 = 'user-42';
    edges.push({ from: plantedUser3, to: 'gpo-workstation-policy', type: R.GENERIC_ALL.label });
    edges.push({ from: 'gpo-workstation-policy', to: 'machine-12', type: R.GPO_APPLIED_TO.label });
    edges.push({ from: 'machine-12', to: 'svc-8', type: R.HAS_SESSION.label });
    edges.push({ from: 'svc-8', to: 'grp-domain-admins', type: R.ADMIN_TO.label });

    // --- Planted Attack Path #4 (3 hops): Kerberoasting Service Account -> Domain Controller Admin -> Admin ---
    const plantedUser4 = 'user-29';
    edges.push({ from: plantedUser4, to: 'svc-4', type: R.KERBEROASTABLE.label });
    edges.push({ from: 'svc-4', to: 'machine-0', type: R.ADMIN_TO.label });
    edges.push({ from: 'machine-0', to: 'grp-domain-admins', type: R.ADMIN_TO.label });

    console.log(`Creating ${edges.length} relationships...`);
    for (const [type, weight] of Object.entries(R).map(([, v]) => [v.label, v.weight])) {
      const batch = edges.filter((e) => e.type === type);
      if (!batch.length) continue;
      await session.run(
        `UNWIND $edges AS e
         MATCH (a {id: e.from}), (b {id: e.to})
         CREATE (a)-[r:${type} {weight: $weight}]->(b)`,
        { edges: batch, weight }
      );
    }

    console.log('Seed complete.');
    console.log(`Loaded ${nodes.length} nodes and ${edges.length} relationships.`);
    console.log(`[Planted Path 1] ${plantedUser1} -> ${plantedMachine1} -> ${plantedSvc1} -> grp-domain-admins`);
    console.log(`[Planted Path 2] ${plantedUser2} -> ${plantedMachine2a} -> ${plantedMachine2b} -> ${plantedSvc2} -> grp-domain-admins`);
    console.log(`[Planted Path 3] ${plantedUser3} -> gpo-workstation-policy -> machine-12 -> svc-8 -> grp-domain-admins`);
    console.log(`[Planted Path 4] ${plantedUser4} -> svc-4 (Kerberoasting) -> machine-0 (DC) -> grp-domain-admins`);
  } finally {
    await session.close();
    await closeDriver();
  }
}

seed().catch((err) => {
  console.error(err);
  process.exit(1);
});
