const neo4j = require('neo4j-driver');
const { driver } = require('../config/db');
const { RELATIONSHIP_TYPES } = require('../config/relationshipTypes');

const WEIGHT_BY_LABEL = Object.fromEntries(
  Object.values(RELATIONSHIP_TYPES).map((r) => [r.label, r.weight])
);

/** Fetch the whole graph (used to render the frontend visualization). */
async function getFullGraph() {
  const session = driver.session();
  try {
    const result = await session.run(
      `MATCH (n)
       OPTIONAL MATCH (n)-[r]->(m)
       RETURN n, r, m`
    );

    const nodesById = new Map();
    const links = [];

    for (const record of result.records) {
      const n = record.get('n');
      const m = record.get('m');
      const r = record.get('r');

      if (n && !nodesById.has(n.properties.id)) {
        nodesById.set(n.properties.id, {
          id: n.properties.id,
          name: n.properties.name,
          type: n.labels[0],
          critical: !!n.properties.critical,
        });
      }
      if (m && !nodesById.has(m.properties.id)) {
        nodesById.set(m.properties.id, {
          id: m.properties.id,
          name: m.properties.name,
          type: m.labels[0],
          critical: !!m.properties.critical,
        });
      }
      if (r) {
        links.push({
          id: r.elementId || (r.identity.toNumber ? r.identity.toNumber() : r.identity),
          source: n.properties.id,
          target: m.properties.id,
          type: r.type,
          weight: r.properties.weight,
        });
      }
    }

    return { nodes: [...nodesById.values()], links };
  } finally {
    await session.close();
  }
}

/**
 * Find attack paths between two nodes, up to maxHops, ranked by exploit
 * cost (sum of edge weights - lower = easier real-world attack path).
 */
async function findAttackPaths(fromId, toId, maxHops = 6, limit = 5) {
  const session = driver.session();
  try {
    const result = await session.run(
      `MATCH (start {id: $fromId}), (end {id: $toId})
       MATCH p = (start)-[*1..${maxHops}]->(end)
       WITH p, reduce(cost = 0, r IN relationships(p) | cost + r.weight) AS totalCost
       RETURN p, totalCost
       ORDER BY totalCost ASC
       LIMIT $limit`,
      { fromId, toId, limit: neo4j.int(limit) }
    );

    return result.records.map((record) => {
      const path = record.get('p');
      const totalCost = record.get('totalCost');
      const steps = path.segments.map((seg) => ({
        from: seg.start.properties.id,
        fromName: seg.start.properties.name,
        to: seg.end.properties.id,
        toName: seg.end.properties.name,
        relationship: seg.relationship.type,
        relId: seg.relationship.elementId || (seg.relationship.identity.toNumber
          ? seg.relationship.identity.toNumber()
          : seg.relationship.identity),
      }));
      return {
        hops: steps.length,
        totalCost,
        riskScore: scoreFromCost(totalCost, steps.length),
        steps,
      };
    });
  } finally {
    await session.close();
  }
}

/** Simple 0-100 risk score: shorter, lower-cost paths score higher. */
function scoreFromCost(totalCost, hops) {
  const raw = 100 - totalCost * 4 - hops * 2;
  return Math.max(5, Math.min(100, Math.round(raw)));
}

/** All nodes reachable from a starting node - "if this is compromised, what's exposed". */
async function getBlastRadius(nodeId, maxHops = 6) {
  const session = driver.session();
  try {
    const result = await session.run(
      `MATCH (start {id: $nodeId})
       MATCH (start)-[*1..${maxHops}]->(reachable)
       RETURN DISTINCT reachable.id AS id, reachable.name AS name,
              labels(reachable)[0] AS type, reachable.critical AS critical`,
      { nodeId }
    );
    return result.records.map((r) => ({
      id: r.get('id'),
      name: r.get('name'),
      type: r.get('type'),
      critical: r.get('critical'),
    }));
  } finally {
    await session.close();
  }
}

/**
 * Remediation simulation: re-run path-finding while excluding one
 * relationship (by its internal id), to show whether removing that
 * single privilege breaks the attack path.
 */
async function simulateRemediation(fromId, toId, excludeRelId, maxHops = 6) {
  const session = driver.session();
  try {
    const result = await session.run(
      `MATCH (start {id: $fromId}), (end {id: $toId})
       MATCH p = (start)-[*1..${maxHops}]->(end)
       WHERE NOT $excludeRelId IN [r IN relationships(p) | elementId(r)]
         AND NOT $excludeRelId IN [r IN relationships(p) | toString(id(r))]
       RETURN count(p) AS remainingPaths
       LIMIT 1`,
      { fromId, toId, excludeRelId: String(excludeRelId) }
    );
    const remainingPaths = result.records[0].get('remainingPaths').toNumber();
    return {
      pathEliminated: remainingPaths === 0,
      remainingPathCount: remainingPaths,
    };
  } finally {
    await session.close();
  }
}

module.exports = {
  getFullGraph,
  findAttackPaths,
  getBlastRadius,
  simulateRemediation,
};
