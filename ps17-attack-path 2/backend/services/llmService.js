/**
 * ZENITH — Live AI Reasoning Layer with NVIDIA NIM
 *
 * CRITICAL ARCHITECTURAL BOUNDARY:
 * This service is strictly a post-processing narration and threat reasoning layer.
 * All attack paths, weights, and risk scores are computed mathematically by Neo4j Cypher.
 * Every explanation is generated dynamically from the CURRENT attack path payload.
 */

const MITRE_TECHNIQUE_MAP = {
  MemberOf: {
    id: 'T1078.002',
    name: 'Valid Accounts: Domain Accounts',
    tactics: ['Persistence', 'Privilege Escalation'],
    description: 'Adversary leverages inherited rights from security group membership without explicit credential theft.',
    detection: 'Monitor Windows Event 4728/4729 for unexpected group membership modifications.',
  },
  AdminTo: {
    id: 'T1078.003',
    name: 'Domain Accounts: Local Administrator Rights',
    tactics: ['Privilege Escalation', 'Lateral Movement'],
    description: 'Local administrator rights grant full control over host filesystems, processes, and memory.',
    detection: 'Audit local Administrators group membership changes via Event ID 4732.',
  },
  CanRDP: {
    id: 'T1021.001',
    name: 'Remote Services: Remote Desktop Protocol',
    tactics: ['Lateral Movement'],
    description: 'Interactive GUI access over port 3389 allows operator-driven lateral traversal onto the host.',
    detection: 'Correlate Event ID 4624 (Logon Type 10) with network connection telemetry on TCP port 3389.',
  },
  HasSession: {
    id: 'T1003.001',
    name: 'OS Credential Dumping: LSASS Memory',
    tactics: ['Credential Access'],
    description: 'An elevated user or service account has an active or cached session in LSASS memory vulnerable to ticket harvesting.',
    detection: 'Monitor Sysmon Event ID 10 (ProcessAccess to lsass.exe) with granted access masks like 0x1010 or 0x1FFFFF.',
  },
  CanResetPasswordOf: {
    id: 'T1098',
    name: 'Account Manipulation: Password Reset',
    tactics: ['Persistence', 'Privilege Escalation'],
    description: 'Active Directory DACL rights allow resetting the password of the target account without current credentials.',
    detection: 'Audit Windows Security Event ID 4724 (An attempt was made to reset an account password) and Event ID 5136.',
  },
  Owns: {
    id: 'T1222',
    name: 'File and Directory Permissions Modification: Object Ownership',
    tactics: ['Defense Evasion', 'Privilege Escalation'],
    description: 'Object owner has inherent right to overwrite the Discretionary Access Control List (DACL).',
    detection: 'Detect Event ID 4670 (Permissions on an object were changed) and Active Directory DS changes (Event 5136).',
  },
  TrustedBy: {
    id: 'T1484',
    name: 'Domain Trust / Delegation Abuse',
    tactics: ['Defense Evasion', 'Lateral Movement'],
    description: 'Kerberos constrained/unconstrained delegation or machine trust allows impersonating arbitrary accounts.',
    detection: 'Inspect msDS-AllowedToDelegateTo attributes and monitor Event ID 4769 for abnormal TGS ticket options.',
  },
  ExecuteDCOM: {
    id: 'T1021.003',
    name: 'Remote Services: Distributed COM',
    tactics: ['Lateral Movement'],
    description: 'Abuse of DCOM applications (e.g. MMC20.Application, ShellWindows) to execute code remotely without interactive login.',
    detection: 'Track RPC endpoint mapper connections (TCP 135) followed by instantiations of suspicious CLSIDs.',
  },
  Kerberoastable: {
    id: 'T1558.003',
    name: 'Steal or Forge Kerberos Tickets: Kerberoasting',
    tactics: ['Credential Access'],
    description: 'Any authenticated user can request TGS tickets for SPN-bearing service accounts and crack password hashes offline.',
    detection: 'Alert on Windows Event ID 4769 with Ticket Encryption Type 0x17 (RC4) requested by non-standard user accounts.',
  },
  GenericAll: {
    id: 'T1222.001',
    name: 'Active Directory Permissions: GenericAll Full Control',
    tactics: ['Privilege Escalation', 'Persistence'],
    description: 'Full discretionary access control rights grant complete authority to alter group membership or reset credentials.',
    detection: 'Monitor Active Directory directory service changes via Windows Security Event ID 5136.',
  },
  GPOAppliedTo: {
    id: 'T1484.001',
    name: 'Group Policy Modification',
    tactics: ['Defense Evasion', 'Privilege Escalation'],
    description: 'Malicious GPO modifications automatically propagate to all linked endpoints on the next 90-minute GPUpdate cycle.',
    detection: 'Alert on modifications to SYSVOL policies and Event ID 5136/5137 for Group Policy Container objects.',
  },
};

const SYSTEM_PROMPT = `You are ZENITH AI, a Tier-0 Active Directory & Identity Threat Analysis Intelligence Engine.
Analyze the following attack path context extracted directly from the live identity graph database (Neo4j).

CRITICAL INSTRUCTIONS:
1. Ground your analysis strictly on the verified facts provided in the payload rather than inventing relationships or entities.
2. Keep the analysis concise, technically accurate, and suitable for both security engineers and hackathon judges.
3. Return structured JSON only. Do not wrap output in markdown ticks (no \`\`\`json or \`\`\`). Return ONLY the raw JSON object.

The output JSON MUST conform to this exact schema:
{
  "executiveSummary": "Concise executive overview of the attack chain threat, compromise impact, and operational context.",
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "attackNarrative": "Step-by-step technical breakdown of how an adversary leverages these specific privilege edges to move laterally and escalate to Tier-0.",
  "stepAnalysis": [
    {
      "relationship": "Exact relationship name from step",
      "mitreTechnique": "MITRE ATT&CK technique ID and name (e.g. T1021.001 - Remote Desktop Protocol)",
      "explanation": "Technical mechanism and adversary action at this specific hop."
    }
  ],
  "primaryChokepoint": {
    "relationship": "Exact relationship name at the primary chokepoint",
    "reason": "Detailed architectural rationale for why severing this specific edge neutralizes the attack path with minimal operational impact."
  },
  "detectionOpportunities": [
    "Specific Windows Event ID or network telemetry detection mechanism"
  ],
  "recommendations": [
    "Concrete actionable hardening or remediation step"
  ],
  "verifiedFacts": [
    "Verified fact extracted directly from current graph state"
  ],
  "reasoning": "Underlying graph reasoning and threat model rationale explaining why this path was chosen over alternative routes."
}`;

/**
 * Constructs the canonical structured request payload from the actual path object.
 */
function buildAttackPathPayload(fromId, toId, pathData) {
  const steps = pathData.steps || [];
  const hops = pathData.hops || steps.length;
  const totalCost = pathData.totalCost || 0;
  const riskScore = pathData.riskScore || 50;

  // Derive source node details
  const sourceNode = pathData.source || {
    id: fromId || (steps[0] ? steps[0].from : 'unknown-source'),
    name: steps[0] ? (steps[0].fromName || steps[0].from) : fromId,
    type: steps[0] ? (steps[0].fromType || 'User') : 'User',
  };

  // Derive target node details
  const lastStep = steps[steps.length - 1];
  const targetNode = pathData.target || {
    id: toId || (lastStep ? lastStep.to : 'unknown-target'),
    name: lastStep ? (lastStep.toName || lastStep.to) : toId,
    type: lastStep ? (lastStep.toType || 'Group') : 'Group',
    critical: true,
  };

  // Build clean normalized steps
  const normalizedSteps = steps.map((s) => ({
    from: s.from,
    fromName: s.fromName || s.from,
    relationship: s.relationship,
    weight: typeof s.weight === 'number' ? s.weight : 1,
    to: s.to,
    toName: s.toName || s.to,
    relId: s.relId,
  }));

  // Mathematically determine primary chokepoint:
  // In attack graphs, the chokepoint is the highest-leverage intermediate pivot edge.
  // Prefer intermediate steps (excluding endpoint boundary) sorted by lowest weight (easiest lateral hop).
  let chokepointStep;
  if (normalizedSteps.length > 2) {
    const intermediates = normalizedSteps.slice(1, -1);
    chokepointStep = [...intermediates].sort((a, b) => a.weight - b.weight)[0];
  } else if (normalizedSteps.length === 2) {
    chokepointStep = normalizedSteps[1];
  } else if (normalizedSteps.length === 1) {
    chokepointStep = normalizedSteps[0];
  } else {
    chokepointStep = { from: sourceNode.id, relationship: 'DirectAccess', to: targetNode.id };
  }

  return {
    source: {
      id: sourceNode.id,
      name: sourceNode.name,
      type: sourceNode.type,
    },
    target: {
      id: targetNode.id,
      name: targetNode.name,
      type: targetNode.type,
      critical: targetNode.critical !== undefined ? targetNode.critical : true,
    },
    path: {
      hops,
      totalCost,
      riskScore,
    },
    steps: normalizedSteps.map(({ from, relationship, weight, to }) => ({
      from,
      relationship,
      weight,
      to,
    })),
    chokepoint: {
      from: chokepointStep.from,
      relationship: chokepointStep.relationship,
      to: chokepointStep.to,
    },
    _rawSteps: normalizedSteps, // Kept internally for name lookups & relIds
  };
}

/**
 * Generates the deterministic fallback response adhering strictly to the schema
 * whenever NVIDIA NIM is unavailable or returns an error.
 */
function generateDeterministicFallback(payload, reasonNotice = null) {
  const { source, target, path, steps, chokepoint, _rawSteps } = payload;
  const rawSteps = _rawSteps || steps;

  const severity =
    path.riskScore >= 75 ? 'CRITICAL' : path.riskScore >= 50 ? 'HIGH' : path.riskScore >= 30 ? 'MEDIUM' : 'LOW';

  const executiveSummary =
    `Adversaries compromising initial identity '${source.name || source.id}' can achieve full control of ` +
    `Tier-0 asset '${target.name || target.id}' across ${path.hops} sequential lateral hops with total exploit ` +
    `friction cost ${path.totalCost} (Risk Score: ${path.riskScore}/100). Graph traversal reveals that intermediate ` +
    `privilege delegations allow traversal without raising traditional brute-force security alarms.`;

  const attackNarrative =
    `The attack chain initiates at identity '${source.name || source.id}' (${source.type}). ` +
    steps
      .map((s, idx) => {
        const raw = rawSteps[idx] || s;
        const fromName = raw.fromName || s.from;
        const toName = raw.toName || s.to;
        return `At Hop ${idx + 1}, the adversary leverages [${s.relationship}] (friction: ${s.weight}) to pivot from '${fromName}' to '${toName}'.`;
      })
      .join(' ') +
    ` This culminates in full compromise of target '${target.name || target.id}'.`;

  const stepAnalysis = steps.map((s, idx) => {
    const raw = rawSteps[idx] || s;
    const tech = MITRE_TECHNIQUE_MAP[s.relationship] || {
      id: 'T1078',
      name: s.relationship,
      description: `Privilege relationship [${s.relationship}] with exploit friction weight ${s.weight}.`,
    };
    return {
      relationship: s.relationship,
      mitreTechnique: `${tech.id} - ${tech.name}`,
      explanation:
        tech.description ||
        `Attacker leverages [${s.relationship}] from '${raw.fromName || s.from}' to reach '${raw.toName || s.to}'.`,
    };
  });

  const primaryChokepoint = {
    relationship: chokepoint.relationship,
    reason:
      `Severing the privilege edge '${chokepoint.from} --[${chokepoint.relationship}]--> ${chokepoint.to}' ` +
      `eliminates this critical lateral bridge, isolating Tier-0 with minimal disruption to daily administrative workflows.`,
  };

  const detectionOpportunities = steps.map((s) => {
    const tech = MITRE_TECHNIQUE_MAP[s.relationship];
    if (tech && tech.detection) return tech.detection;
    return `Monitor Windows Security Event logs for abnormal [${s.relationship}] traversal events and cross-tier RPC traffic.`;
  });

  const recommendations = [
    `CRITICAL CHOKEPOINT: Revoke privilege link '${chokepoint.from} --[${chokepoint.relationship}]--> ${chokepoint.to}' to dismantle this primary attack path.`,
    `Enable Windows Defender Credential Guard and Restricted Admin mode to prevent LSASS credential harvesting on intermediate machines.`,
    `Enforce Tiered Administrative Architecture (PAW) ensuring Tier-0 administrative credentials never touch lower-tier hosts.`,
    `Audit Active Directory DACL permissions and purge stale delegations over '${target.name || target.id}'.`,
  ];

  const verifiedFacts = [
    `Initial Compromise Identity: ${source.name || source.id} (${source.type})`,
    `Target Asset: ${target.name || target.id} (${target.type})${target.critical ? ' [Tier-0 Critical]' : ''}`,
    `Dijkstra Shortest Attack Path: ${path.hops} sequential hops (Cumulative Exploit Cost: ${path.totalCost})`,
    `Deterministic Risk Score: ${path.riskScore}/100`,
    `Identified Chokepoint: ${chokepoint.from} --[${chokepoint.relationship}]--> ${chokepoint.to}`,
  ];

  const reasoning =
    `Neo4j Dijkstra pathfinding ranked this sequence as the optimal attack route because it minimizes cumulative ` +
    `adversary exploit friction (cost: ${path.totalCost}). Compared to alternative routes involving hardened boundaries, ` +
    `this path exploits pre-existing administrative sessions and misconfigured delegation rights.`;

  const notice = reasonNotice || 'AI analysis unavailable — deterministic graph analysis is still active.';

  return {
    executiveSummary,
    severity,
    attackNarrative,
    stepAnalysis,
    primaryChokepoint,
    detectionOpportunities: [...new Set(detectionOpportunities)],
    recommendations,
    verifiedFacts,
    reasoning,
    isLive: false,
    notice,
    requestPayload: {
      source: payload.source,
      target: payload.target,
      path: payload.path,
      steps: payload.steps,
      chokepoint: payload.chokepoint,
    },
    // Backward compatibility aliases for existing frontend & test suites:
    threatLevel: severity,
    riskScore: path.riskScore,
    totalCost: path.totalCost,
    hops: path.hops,
    source: source.name || source.id,
    target: target.name || target.id,
    mitreTechniques: stepAnalysis.map((s, idx) => ({
      step: `${rawSteps[idx]?.fromName || steps[idx]?.from} -> ${rawSteps[idx]?.toName || steps[idx]?.to}`,
      relationship: s.relationship,
      techniqueName: s.mitreTechnique,
      description: s.explanation,
    })),
    chainBreakdown: stepAnalysis.map((s, idx) => ({
      hopNumber: idx + 1,
      source: rawSteps[idx]?.fromName || steps[idx]?.from,
      target: rawSteps[idx]?.toName || steps[idx]?.to,
      technique: s.mitreTechnique,
      attackAction: s.explanation,
      detectionVector: detectionOpportunities[idx] || detectionOpportunities[0],
    })),
    remediationPlaybook: recommendations,
  };
}

/**
 * Validates whether the returned JSON object conforms to the required schema.
 */
function validateLlmResponse(data) {
  if (!data || typeof data !== 'object') return false;
  if (typeof data.executiveSummary !== 'string' || !data.executiveSummary.trim()) return false;
  if (!['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(String(data.severity).toUpperCase())) return false;
  if (typeof data.attackNarrative !== 'string') return false;
  if (!Array.isArray(data.stepAnalysis) || data.stepAnalysis.length === 0) return false;
  if (!data.primaryChokepoint || typeof data.primaryChokepoint !== 'object') return false;
  if (!Array.isArray(data.detectionOpportunities)) return false;
  if (!Array.isArray(data.recommendations)) return false;
  if (!Array.isArray(data.verifiedFacts)) return false;
  if (typeof data.reasoning !== 'string') return false;
  return true;
}

/**
 * Clean raw LLM response text (stripping markdown code ticks if model wrapped it).
 */
function cleanJsonText(rawText) {
  let text = String(rawText || '').trim();
  if (text.startsWith('```json')) {
    text = text.replace(/^```json\s*/i, '').replace(/\s*```$/i, '');
  } else if (text.startsWith('```')) {
    text = text.replace(/^```\s*/i, '').replace(/\s*```$/i, '');
  }
  return text.trim();
}

/**
 * Explain attack path with live NVIDIA NIM or graceful deterministic fallback.
 *
 * @param {Object} inputPayload - Either normalized structured payload or { from, to, path }
 * @param {Object} options - { apiKey, model }
 */
async function explainAttackPath(inputPayload, options = {}) {
  // Normalize payload
  let payload;
  if (inputPayload && inputPayload.source && inputPayload.target && inputPayload.steps) {
    payload = inputPayload;
  } else if (options.fromId && options.toId && inputPayload) {
    payload = buildAttackPathPayload(options.fromId, options.toId, inputPayload);
  } else {
    payload = inputPayload;
  }

  const apiKey = options.apiKey || process.env.NVIDIA_API_KEY;
  const model = options.model || process.env.NVIDIA_MODEL || 'meta/llama-3.1-70b-instruct';

  if (!apiKey || !apiKey.trim()) {
    console.warn('[ZENITH LLM] No NVIDIA_API_KEY detected. Utilizing deterministic graph intelligence fallback.');
    return generateDeterministicFallback(
      payload,
      'AI analysis unavailable — deterministic graph analysis is still active.'
    );
  }

  const cleanPayload = {
    source: payload.source,
    target: payload.target,
    path: payload.path,
    steps: payload.steps,
    chokepoint: payload.chokepoint,
  };

  const userPrompt =
    `Analyze the following active attack path payload from the live Neo4j identity graph:\n\n` +
    JSON.stringify(cleanPayload, null, 2);

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000); // 20s timeout boundary

    const response = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey.trim()}`,
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.2,
        top_p: 0.7,
        max_tokens: 1500,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorBody = await response.text().catch(() => '');
      console.warn(
        `[ZENITH LLM] NVIDIA NIM API returned HTTP ${response.status}: ${errorBody.slice(0, 200)}. Utilizing fallback.`
      );
      return generateDeterministicFallback(
        payload,
        'AI analysis unavailable — deterministic graph analysis is still active.'
      );
    }

    const jsonResp = await response.json();
    const choice = jsonResp.choices && jsonResp.choices[0];
    const rawContent = choice && choice.message && choice.message.content;

    if (!rawContent) {
      console.warn('[ZENITH LLM] NVIDIA NIM returned empty message content. Falling back.');
      return generateDeterministicFallback(
        payload,
        'AI analysis unavailable — deterministic graph analysis is still active.'
      );
    }

    const cleanedText = cleanJsonText(rawContent);
    let parsed;
    try {
      parsed = JSON.parse(cleanedText);
    } catch (parseErr) {
      console.warn('[ZENITH LLM] Malformed JSON from NVIDIA NIM model. Engaging fallback.', parseErr.message);
      return generateDeterministicFallback(
        payload,
        'AI analysis unavailable — deterministic graph analysis is still active.'
      );
    }

    // Normalize severity to uppercase
    if (parsed.severity) {
      parsed.severity = String(parsed.severity).toUpperCase();
    }

    if (!validateLlmResponse(parsed)) {
      console.warn('[ZENITH LLM] Model response failed schema validation. Engaging safe fallback.');
      return generateDeterministicFallback(
        payload,
        'AI analysis unavailable — deterministic graph analysis is still active.'
      );
    }

    // Attach metadata and backward-compatible fields
    const rawSteps = payload._rawSteps || payload.steps;
    return {
      ...parsed,
      isLive: true,
      model,
      timestamp: new Date().toISOString(),
      requestPayload: cleanPayload,
      // Backward compatibility aliases
      threatLevel: parsed.severity,
      riskScore: payload.path.riskScore,
      totalCost: payload.path.totalCost,
      hops: payload.path.hops,
      source: payload.source.name || payload.source.id,
      target: payload.target.name || payload.target.id,
      mitreTechniques: parsed.stepAnalysis.map((s, idx) => ({
        step: `${rawSteps[idx]?.fromName || payload.steps[idx]?.from} -> ${rawSteps[idx]?.toName || payload.steps[idx]?.to}`,
        relationship: s.relationship,
        techniqueName: s.mitreTechnique,
        description: s.explanation,
      })),
      chainBreakdown: parsed.stepAnalysis.map((s, idx) => ({
        hopNumber: idx + 1,
        source: rawSteps[idx]?.fromName || payload.steps[idx]?.from,
        target: rawSteps[idx]?.toName || payload.steps[idx]?.to,
        technique: s.mitreTechnique,
        attackAction: s.explanation,
        detectionVector:
          (parsed.detectionOpportunities && parsed.detectionOpportunities[idx]) ||
          parsed.detectionOpportunities[0] ||
          'Monitor Windows Event logs',
      })),
      remediationPlaybook: parsed.recommendations,
    };
  } catch (err) {
    const errorType = err.name === 'AbortError' ? 'Timeout (20s)' : err.message;
    console.warn(`[ZENITH LLM] Live NVIDIA NIM error (${errorType}). Utilizing deterministic fallback.`);
    return generateDeterministicFallback(
      payload,
      'AI analysis unavailable — deterministic graph analysis is still active.'
    );
  }
}

module.exports = {
  buildAttackPathPayload,
  explainAttackPath,
  generateDeterministicFallback,
  validateLlmResponse,
  MITRE_TECHNIQUE_MAP,
};
