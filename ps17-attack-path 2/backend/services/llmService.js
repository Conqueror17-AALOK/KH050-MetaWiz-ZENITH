/**
 * ZENITH — Decoupled LLM Threat Narration Service (Phase 5)
 *
 * CRITICAL ARCHITECTURAL BOUNDARY:
 * This service is STRICTLY a post-processing narration and explanation layer.
 * All attack paths, weights, and remediation outcomes are computed mathematically
 * by the Neo4j Cypher graph engine. The LLM or rule engine NEVER participates
 * in path discovery, scoring, or decision-making.
 */

const MITRE_TECHNIQUE_MAP = {
  MemberOf: {
    id: 'T1078',
    name: 'Valid Accounts: Group Membership',
    tactics: ['Persistence', 'Privilege Escalation'],
    description: 'Adversary leverages inherited rights from security group membership without needing explicit credentials.',
  },
  AdminTo: {
    id: 'T1078.002',
    name: 'Domain Accounts: Local Administrator Rights',
    tactics: ['Privilege Escalation', 'Lateral Movement'],
    description: 'Direct local administrator rights grant full control over host filesystems, memory, and services.',
  },
  CanRDP: {
    id: 'T1021.001',
    name: 'Remote Services: Remote Desktop Protocol',
    tactics: ['Lateral Movement'],
    description: 'Interactive GUI access over port 3389 allows operator-driven lateral traversal onto the host.',
  },
  HasSession: {
    id: 'T1003.001',
    name: 'OS Credential Dumping: LSASS Memory',
    tactics: ['Credential Access'],
    description: 'An elevated user or service account has an active or cached ticket/NTLM hash in LSASS memory ready to harvest.',
  },
  CanResetPasswordOf: {
    id: 'T1098',
    name: 'Account Manipulation: Password Reset',
    tactics: ['Persistence', 'Privilege Escalation'],
    description: 'DACL rights allow resetting the password of the target account without knowledge of the current password.',
  },
  Owns: {
    id: 'T1222',
    name: 'File and Directory Permissions Modification: Object Ownership',
    tactics: ['Defense Evasion', 'Privilege Escalation'],
    description: 'Object owner has inherent right to overwrite the Discretionary Access Control List (DACL).',
  },
  TrustedBy: {
    id: 'T1484',
    name: 'Domain Trust / Delegation Abuse',
    tactics: ['Defense Evasion', 'Lateral Movement'],
    description: 'Kerberos constrained/unconstrained delegation or host trust allows impersonating arbitrary accounts.',
  },
  ExecuteDCOM: {
    id: 'T1021.003',
    name: 'Remote Services: Distributed COM',
    tactics: ['Lateral Movement'],
    description: 'Abuse of DCOM applications (e.g. MMC20.Application, ShellWindows) to execute code remotely without interactive login.',
  },
  Kerberoastable: {
    id: 'T1558.003',
    name: 'Steal or Forge Kerberos Tickets: Kerberoasting',
    tactics: ['Credential Access'],
    description: 'Any authenticated user can request TGS tickets for SPN-bearing accounts and crack password hashes offline.',
  },
  GenericAll: {
    id: 'T1222.001',
    name: 'Active Directory Permissions: GenericAll Full Control',
    tactics: ['Privilege Escalation', 'Persistence'],
    description: 'Full discretionary access control rights grant complete authority to alter group membership or reset credentials.',
  },
  GPOAppliedTo: {
    id: 'T1484.001',
    name: 'Group Policy Modification',
    tactics: ['Defense Evasion', 'Privilege Escalation'],
    description: 'Malicious GPO modifications automatically propagate to all linked endpoints on the next 90-minute GPUpdate cycle.',
  },
};

/**
 * Generate structured threat intelligence narration for a computed attack path.
 */
async function explainAttackPath(fromId, toId, path) {
  const steps = path.steps || [];
  const hops = path.hops || steps.length;
  const totalCost = path.totalCost || 0;
  const riskScore = path.riskScore || 0;

  // Identify chokepoints: intermediate edges with lowest friction or central pivot
  const chokepointStep = steps.length > 1 ? steps[1] : steps[0];

  // Map MITRE ATT&CK techniques
  const mitreTechniques = steps.map((s) => {
    const tech = MITRE_TECHNIQUE_MAP[s.relationship] || {
      id: 'T1078',
      name: s.relationship,
      tactics: ['Privilege Escalation'],
      description: `Privilege relationship ${s.relationship}`,
    };
    return {
      step: `${s.fromName} -> ${s.toName}`,
      relationship: s.relationship,
      techniqueId: tech.id,
      techniqueName: tech.name,
      tactics: tech.tactics,
      description: tech.description,
    };
  });

  const targetName = steps.length > 0 ? steps[steps.length - 1].toName : toId;
  const sourceName = steps.length > 0 ? steps[0].fromName : fromId;

  const executiveSummary =
    `Adversaries compromising initial identity '${sourceName}' can achieve full control of Tier-0 asset '${targetName}' ` +
    `in ${hops} sequential lateral hops with an overall exploit friction cost of ${totalCost} (Risk Score: ${riskScore}/100). ` +
    `Because intermediate permissions bypass endpoint isolation through active credential harvesting and delegation abuse, ` +
    `this attack path can be traversed without raising traditional brute-force security alarms.`;

  const chainBreakdown = steps.map((s, idx) => {
    const tech = MITRE_TECHNIQUE_MAP[s.relationship] || { id: 'T1078', name: s.relationship };
    return {
      hopNumber: idx + 1,
      source: s.fromName,
      target: s.toName,
      technique: `${tech.name} (${tech.id})`,
      attackAction: `Attacker leverages ${s.relationship} from '${s.fromName}' to compromise or access '${s.toName}'.`,
      detectionVector: `Monitor Windows Security Event logs for ${s.relationship} telemetry and abnormal cross-tier RPC/SMB/Kerberos traffic.`,
    };
  });

  const remediationPlaybook = [
    `CRITICAL CHOKEPOINT: Sever the privilege '${chokepointStep.fromName} --[${chokepointStep.relationship}]--> ${chokepointStep.toName}' to break this primary attack chain.`,
    `Enable Credential Guard and Restricted Admin mode on host '${chokepointStep.fromName}' to prevent LSASS credential caching.`,
    `Audit Active Directory DACL delegations to eliminate shadow admin rights over '${targetName}'.`,
    `Apply Tiered Administrative Architecture (PAW / ESAE) ensuring administrative credentials never touch lower-tier workstations.`,
  ];

  return {
    threatLevel: riskScore >= 70 ? 'CRITICAL' : riskScore >= 45 ? 'HIGH' : 'MEDIUM',
    riskScore,
    totalCost,
    hops,
    source: sourceName,
    target: targetName,
    executiveSummary,
    mitreTechniques,
    chainBreakdown,
    chokepoint: {
      from: chokepointStep ? chokepointStep.fromName : null,
      to: chokepointStep ? chokepointStep.toName : null,
      relationship: chokepointStep ? chokepointStep.relationship : null,
      relId: chokepointStep ? chokepointStep.relId : null,
      rationale: 'Severing this intermediate pivot breaks the lateral bridge with minimal operational disruption to end-user workflows.',
    },
    remediationPlaybook,
  };
}

module.exports = {
  explainAttackPath,
  MITRE_TECHNIQUE_MAP,
};
