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
    const { dataset } = req.query;
    const graph = await graphService.getFullGraph(dataset);
    res.json(graph);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch graph' });
  }
});

// GET /api/paths?from=user-3&to=grp-domain-admins
router.get('/paths', async (req, res) => {
  const { from, to, dataset } = req.query;
  if (!from || !to) {
    return res.status(400).json({ error: 'from and to query params are required' });
  }
  try {
    const paths = await graphService.findAttackPaths(from, to, 6, 5, dataset);
    res.json({ from, to, dataset, paths });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to compute paths' });
  }
});

// GET /api/blast-radius/:nodeId
router.get('/blast-radius/:nodeId', async (req, res) => {
  try {
    const { dataset } = req.query;
    const reachable = await graphService.getBlastRadius(req.params.nodeId, 6, dataset);
    res.json({ nodeId: req.params.nodeId, dataset, reachableCount: reachable.length, reachable });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to compute blast radius' });
  }
});

// POST /api/simulate-remediation  { from, to, excludeRelId, dataset }
router.post('/simulate-remediation', async (req, res) => {
  const { from, to, excludeRelId, dataset } = req.body;
  if (!from || !to || excludeRelId === undefined) {
    return res.status(400).json({ error: 'from, to, and excludeRelId are required' });
  }
  try {
    const result = await graphService.simulateRemediation(from, to, excludeRelId, 6, dataset);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to simulate remediation' });
  }
});

// POST /api/explain-path (Live AI Reasoning Layer with NVIDIA NIM)
router.post('/explain-path', async (req, res) => {
  try {
    const { from, to, path, apiKey, model } = req.body;
    const headerApiKey = req.headers['x-nvidia-api-key'];
    const activeApiKey = apiKey || headerApiKey || process.env.NVIDIA_API_KEY;

    let payload;
    if (req.body.source && req.body.target && req.body.steps) {
      // Incoming body is already the canonical structured payload
      payload = req.body;
    } else if (path && path.steps) {
      // Construct structured payload from path object
      payload = llmService.buildAttackPathPayload(from, to, path);
    } else {
      return res.status(400).json({ error: 'Valid attack path object with steps or structured payload is required' });
    }

    const explanation = await llmService.explainAttackPath(payload, {
      apiKey: activeApiKey,
      model,
      fromId: from,
      toId: to,
    });
    res.json(explanation);
  } catch (err) {
    console.error('[ZENITH API] Error in /api/explain-path:', err);
    res.status(500).json({
      error: 'Failed to generate threat explanation',
      message: err.message,
    });
  }
});

// POST /api/inject (Phase 6 - Live Judge Scenario Injection)
router.post('/inject', async (req, res) => {
  const { from, to, relationshipType, dataset } = req.body;
  if (!from || !to || !relationshipType) {
    return res.status(400).json({ error: 'from, to, and relationshipType are required' });
  }
  try {
    const result = await graphService.injectRelationship(from, to, relationshipType, dataset);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Failed to inject live scenario relationship' });
  }
});

// POST /api/adsynth/import - import ADSynth dataset from a directory or file path
router.post('/adsynth/import', async (req, res) => {
  try {
    const { importAdsynthToNeo4j } = require('../scripts/adsynthManager');
    const targetPath = req.body?.path || process.env.ADSYNTH_OUTPUT_DIR || 'data/adsynth';
    const result = await importAdsynthToNeo4j(targetPath);
    res.json(result);
  } catch (err) {
    console.error('[ZENITH API] Error importing ADSynth:', err);
    res.status(500).json({ error: err.message || 'Failed to import ADSynth dataset' });
  }
});

// POST /api/adsynth/test - run in-memory test on ADSynth dataset
router.post('/adsynth/test', async (req, res) => {
  try {
    const { testAdsynthDataset } = require('../scripts/adsynthManager');
    const targetPath = req.body?.path || process.env.ADSYNTH_OUTPUT_DIR || 'data/adsynth';
    const result = await testAdsynthDataset(targetPath);
    res.json(result);
  } catch (err) {
    console.error('[ZENITH API] Error testing ADSynth:', err);
    res.status(500).json({ error: err.message || 'Failed to test ADSynth dataset' });
  }
});

// POST /api/seed/default - reset/seed canonical 129-node benchmark dataset
router.post('/seed/default', async (req, res) => {
  try {
    const { seed } = require('../scripts/seedData');
    const result = await seed(false);
    res.json({ success: true, ...result, message: 'Seeded canonical 129-node benchmark dataset' });
  } catch (err) {
    console.error('[ZENITH API] Error seeding benchmark dataset:', err);
    res.status(500).json({ error: err.message || 'Failed to seed benchmark dataset' });
  }
});

module.exports = router;
