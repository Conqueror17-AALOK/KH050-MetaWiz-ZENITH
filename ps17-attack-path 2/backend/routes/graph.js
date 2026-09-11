const express = require('express');
const router = express.Router();
const graphService = require('../services/graphService');
const llmService = require('../services/llmService');
const { RELATIONSHIP_TYPES } = require('../config/relationshipTypes');

// GET /api/relationship-types - list of supported attack vectors and weights
router.get('/relationship-types', (req, res) => {
  res.json(RELATIONSHIP_TYPES);
});

// GET /api/graph - full node/edge set for the frontend visualization
router.get('/graph', async (req, res) => {
  try {
    const graph = await graphService.getFullGraph();
    res.json(graph);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch graph' });
  }
});

// GET /api/paths?from=user-3&to=grp-domain-admins
router.get('/paths', async (req, res) => {
  const { from, to } = req.query;
  if (!from || !to) {
    return res.status(400).json({ error: 'from and to query params are required' });
  }
  try {
    const paths = await graphService.findAttackPaths(from, to);
    res.json({ from, to, paths });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to compute paths' });
  }
});

// GET /api/blast-radius/:nodeId
router.get('/blast-radius/:nodeId', async (req, res) => {
  try {
    const reachable = await graphService.getBlastRadius(req.params.nodeId);
    res.json({ nodeId: req.params.nodeId, reachableCount: reachable.length, reachable });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to compute blast radius' });
  }
});

// POST /api/simulate-remediation  { from, to, excludeRelId }
router.post('/simulate-remediation', async (req, res) => {
  const { from, to, excludeRelId } = req.body;
  if (!from || !to || excludeRelId === undefined) {
    return res.status(400).json({ error: 'from, to, and excludeRelId are required' });
  }
  try {
    const result = await graphService.simulateRemediation(from, to, excludeRelId);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to simulate remediation' });
  }
});

// POST /api/explain-path (Phase 5 - Decoupled Threat Narration)
router.post('/explain-path', async (req, res) => {
  const { from, to, path } = req.body;
  if (!path || !path.steps) {
    return res.status(400).json({ error: 'Valid attack path object with steps is required' });
  }
  try {
    const explanation = await llmService.explainAttackPath(from, to, path);
    res.json(explanation);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to generate threat explanation' });
  }
});

// POST /api/inject (Phase 6 - Live Judge Scenario Injection)
router.post('/inject', async (req, res) => {
  const { from, to, relationshipType } = req.body;
  if (!from || !to || !relationshipType) {
    return res.status(400).json({ error: 'from, to, and relationshipType are required' });
  }
  try {
    const result = await graphService.injectRelationship(from, to, relationshipType);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Failed to inject live scenario relationship' });
  }
});

module.exports = router;
