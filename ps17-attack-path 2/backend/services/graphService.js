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
       WITH p, end, reduce(cost = 0, r IN relationships(p) | cost + r.weight) AS totalCost
       RETURN p, totalCost, end.critical AS isCritical
       ORDER BY totalCost ASC
       LIMIT $limit`,
      { fromId, toId, limit: neo4j.int(limit) }
    );

    return result.records.map((record) => {
      const path = record.get('p');
      const totalCost = record.get('totalCost');
      const isCritical = record.get('isCritical');
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
        riskScore: scoreFromCost(totalCost, steps.length, isCritical),
        steps,
      };
    });
  } finally {
    await session.close();
  }
}

/**
 * Explainable 5-100 risk score for judges:
 * Starts from 85 base (+15 for Tier-0 critical targets) and deducts points
 * proportional to exploit friction (cost * 3.5) and hop length (hops * 2.5).
 */
function scoreFromCost(totalCost, hops, isCritical = true) {
  const base = isCritical ? 100 : 85;
  const raw = base - (totalCost * 3.5) - (hops * 2.5);
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
 * relationship, returning whether the path is eliminated OR the new alternate
 * re-routed path if one still exists.
 */
async function simulateRemediation(fromId, toId, excludeRelId, maxHops = 6) {
  const session = driver.session();
  try {
    const result = await session.run(
      `MATCH (start {id: $fromId}), (end {id: $toId})
       MATCH p = (start)-[*1..${maxHops}]->(end)
       WHERE NOT $excludeRelId IN [r IN relationships(p) | elementId(r)]
         AND NOT $excludeRelId IN [r IN relationships(p) | toString(id(r))]
       WITH p, end, reduce(cost = 0, r IN relationships(p) | cost + r.weight) AS totalCost
       RETURN p, totalCost, end.critical AS isCritical
       ORDER BY totalCost ASC
       LIMIT 1`,
      { fromId, toId, excludeRelId: String(excludeRelId) }
    );

    if (result.records.length === 0) {
      return {
        pathEliminated: true,
        remainingPathCount: 0,
        reRoutedPath: null,
      };
    }

    const record = result.records[0];
    const path = record.get('p');
    const totalCost = record.get('totalCost');
    const isCritical = record.get('isCritical');
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
      pathEliminated: false,
      remainingPathCount: result.records.length,
      reRoutedPath: {
        hops: steps.length,
        totalCost,
        riskScore: scoreFromCost(totalCost, steps.length, isCritical),
        steps,
      },
    };
  } finally {
    await session.close();
  }
}

/**
 * Live scenario injection for judges:
 * Add a new privilege relationship directly into the live graph.
 */
async function injectRelationship(fromId, toId, relationshipType) {
  const relConfig = RELATIONSHIP_TYPES[relationshipType] ||
    Object.values(RELATIONSHIP_TYPES).find((r) => r.label === relationshipType) ||
    { label: relationshipType, weight: 3 };

  const weight = relConfig.weight;
  const label = relConfig.label;

  const session = driver.session();
  try {
    const result = await session.run(
      `MATCH (a {id: $fromId}), (b {id: $toId})
       CREATE (a)-[r:${label} {weight: $weight}]->(b)
       RETURN elementId(r) AS relId, type(r) AS type, r.weight AS weight`,
      { fromId, toId, weight }
    );

    if (result.records.length === 0) {
      throw new Error(`One or both nodes (${fromId}, ${toId}) do not exist in the graph.`);
    }

    const rec = result.records[0];
    return {
      success: true,
      relId: rec.get('relId'),
      type: rec.get('type'),
      weight: rec.get('weight'),
      from: fromId,
      to: toId,
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
  injectRelationship,
};
