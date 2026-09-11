import React, { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import {
  getGraph,
  getPaths,
  getBlastRadius,
  simulateRemediation,
  explainPath,
  injectRelationship,
  getRelationshipTypes,
} from '../api';

const TYPE_COLORS = {
  User: '#38bdf8',          // Cyan
  Group: '#f59e0b',         // Amber
  ServiceAccount: '#ec4899',// Magenta
  Machine: '#10b981',       // Emerald
};

const PRESETS = [
  { label: 'Demo 1: RDP Session (user-3)', from: 'user-3', to: 'grp-domain-admins', desc: 'RDP -> LSASS Cached Session -> Password Reset' },
  { label: 'Demo 2: DCOM Trust (user-17)', from: 'user-17', to: 'grp-domain-admins', desc: 'DCOM Execution -> Machine Trust -> Session -> Admin' },
  { label: 'Demo 3: GPO Abuse (user-42)', from: 'user-42', to: 'grp-domain-admins', desc: 'GenericAll ACL -> GPO Applied -> Session -> Admin' },
  { label: 'Demo 4: Kerberoasting (user-29)', from: 'user-29', to: 'grp-domain-admins', desc: 'Kerberoastable SPN -> DC Admin -> Domain Admin' },
];

export default function GraphView() {
  const fgRef = useRef();

  // Graph state
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [fromId, setFromId] = useState('user-3');
  const [toId, setToId] = useState('grp-domain-admins');
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedLink, setSelectedLink] = useState(null);

  // Path & Intelligence state
  const [pathResult, setPathResult] = useState(null);
  const [highlightLinks, setHighlightLinks] = useState(new Set());
  const [highlightNodes, setHighlightNodes] = useState(new Set());
  const [reroutedLinks, setReroutedLinks] = useState(new Set());
  const [status, setStatus] = useState('Initializing ZENITH Graph Engine...');

  // Blast radius state
  const [blastRadiusData, setBlastRadiusData] = useState(null);
  const [blastNodes, setBlastNodes] = useState(new Set());

  // Remediation simulation state
  const [remediationState, setRemediationState] = useState(null);

  // LLM threat intelligence state
  const [llmBriefing, setLlmBriefing] = useState(null);
  const [isGeneratingBriefing, setIsGeneratingBriefing] = useState(false);

  // Interactive Risk Calculator state
  const [calcHops, setCalcHops] = useState(3);
  const [calcCost, setCalcCost] = useState(9);
  const [calcTargetTier, setCalcTargetTier] = useState('tier0');
  const [calcSurfaceFactor, setCalcSurfaceFactor] = useState(5);

  const calcBase = useMemo(() => {
    if (calcTargetTier === 'tier0') return 100;
    if (calcTargetTier === 'tier1') return 90;
    return 85;
  }, [calcTargetTier]);

  const calculatedRiskScore = useMemo(() => {
    const raw = calcBase - (calcCost * 3.5) - (calcHops * 2.5) + Number(calcSurfaceFactor);
    return Math.max(5, Math.min(100, Math.round(raw)));
  }, [calcBase, calcCost, calcHops, calcSurfaceFactor]);

  const syncCalcFromActivePath = useCallback(() => {
    if (pathResult?.paths?.[0]) {
      const p = pathResult.paths[0];
      setCalcHops(p.hops || 3);
      setCalcCost(p.totalCost || 9);
      const isCrit = p.target?.critical !== undefined ? p.target.critical : true;
      setCalcTargetTier(isCrit ? 'tier0' : 'tier2');
      const hasSession = p.steps?.some((s) => s.relationship === 'HasSession');
      const hasGenericAll = p.steps?.some((s) => s.relationship === 'GenericAll' || s.relationship === 'CanResetPasswordOf');
      setCalcSurfaceFactor(hasGenericAll ? 10 : hasSession ? 5 : 0);
      setStatus(`Synced Risk Calculator with active path: ${p.hops} hops, friction cost ${p.totalCost}.`);
    }
  }, [pathResult]);

  // Live Scenario Injection state
  const [showInjectModal, setShowInjectModal] = useState(false);
  const [injectFrom, setInjectFrom] = useState('');
  const [injectTo, setInjectTo] = useState('grp-domain-admins');
  const [injectType, setInjectType] = useState('CanRDP');
  const [relationshipTypes, setRelationshipTypes] = useState({});
  const [injectStatus, setInjectStatus] = useState('');

  // Active tab in sidebar: 'paths' | 'blast' | 'briefing'
  const [activeTab, setActiveTab] = useState('paths');

  // Load initial graph & relationship types
  const loadGraph = useCallback(async () => {
    setStatus('Loading Neo4j identity graph...');
    try {
      const [data, relTypes] = await Promise.all([
        getGraph(),
        getRelationshipTypes().catch(() => ({})),
      ]);
      setGraphData(data);
      setRelationshipTypes(relTypes);
      setStatus(`Connected to Neo4j. Loaded ${data.nodes.length} nodes & ${data.links.length} privilege edges.`);
    } catch (err) {
      setStatus(`Error connecting to graph: ${err.message}`);
    }
  }, []);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  // Path finding execution
  const runPathFind = useCallback(async (customFrom, customTo) => {
    const fId = customFrom || fromId;
    const tId = customTo || toId;
    if (!fId || !tId) return;

    setStatus(`Computing Dijkstra-weighted attack paths from '${fId}' to '${tId}'...`);
    setRemediationState(null);
    setReroutedLinks(new Set());
    setLlmBriefing(null);

    try {
      const result = await getPaths(fId, tId);
      setPathResult(result);
      if (result.paths && result.paths.length > 0) {
        const best = result.paths[0];
        const linkKeys = new Set(best.steps.map((s) => `${s.from}->${s.to}`));
        const nodeKeys = new Set(best.steps.flatMap((s) => [s.from, s.to]));
        setHighlightLinks(linkKeys);
        setHighlightNodes(nodeKeys);
        setStatus(`Discovered ${result.paths.length} attack path(s). Primary path: ${best.hops} hops, Risk ${best.riskScore}/100.`);
        setActiveTab('paths');

        // Center on path
        if (fgRef.current && best.steps.length > 0) {
          const firstNode = graphData.nodes.find((n) => n.id === best.steps[0].from);
          if (firstNode) {
            fgRef.current.centerAt(firstNode.x, firstNode.y, 800);
            fgRef.current.zoom(2.5, 800);
          }
        }
      } else {
        setHighlightLinks(new Set());
        setHighlightNodes(new Set());
        setStatus(`Zero attack paths found between '${fId}' and '${tId}'. Target is secure from this identity.`);
      }
    } catch (err) {
      setStatus(`Path computation failed: ${err.message}`);
    }
  }, [fromId, toId, graphData.nodes]);

  // Blast radius execution
  const runBlastRadius = useCallback(async (targetNodeId) => {
    const nodeId = targetNodeId || selectedNode?.id || fromId;
    if (!nodeId) return;

    setStatus(`Calculating blast radius for node '${nodeId}'...`);
    try {
      const data = await getBlastRadius(nodeId);
      setBlastRadiusData(data);
      const reachableIds = new Set(data.reachable.map((n) => n.id));
      reachableIds.add(nodeId);
      setBlastNodes(reachableIds);
      setActiveTab('blast');
      setStatus(`Blast radius for '${nodeId}': ${data.reachableCount} downstream reachable entities (${data.reachable.filter((n) => n.critical).length} critical).`);
    } catch (err) {
      setStatus(`Blast radius calculation failed: ${err.message}`);
    }
  }, [selectedNode, fromId]);

  // Clear blast radius
  const clearBlastRadius = () => {
    setBlastRadiusData(null);
    setBlastNodes(new Set());
  };

  // Remediation simulation on ANY edge
  const runRemediationOnEdge = useCallback(async (relId, edgeLabel) => {
    if (!fromId || !toId) return;
    setStatus(`Simulating revocation of edge '${edgeLabel || relId}'...`);

    try {
      const result = await simulateRemediation(fromId, toId, relId);
      setRemediationState(result);

      if (result.pathEliminated) {
        // Chokepoint severed!
        setHighlightLinks(new Set());
        setReroutedLinks(new Set());
        setHighlightNodes(new Set([fromId, toId]));
        setStatus(`REMEDIATION SUCCESSFUL: Revoking edge eliminated all attack paths between '${fromId}' and '${toId}'!`);
      } else if (result.reRoutedPath) {
        // Path rerouted
        const reroutedLinkKeys = new Set(result.reRoutedPath.steps.map((s) => `${s.from}->${s.to}`));
        setHighlightLinks(new Set());
        setReroutedLinks(reroutedLinkKeys);
        setHighlightNodes(new Set(result.reRoutedPath.steps.flatMap((s) => [s.from, s.to])));
        setStatus(`PATH REROUTED: Attack path survives via ${result.remainingPathCount} alternate route(s). Alternate path rendered in amber.`);
      }
    } catch (err) {
      setStatus(`Remediation simulation error: ${err.message}`);
    }
  }, [fromId, toId]);

  // Live AI Threat Reasoning generation
  const runExplainPath = useCallback(async () => {
    if (!pathResult || !pathResult.paths || pathResult.paths.length === 0) return;
    setIsGeneratingBriefing(true);
    setStatus('Generating AI threat analysis on dataset attack path...');

    try {
      const best = pathResult.paths[0];
      const briefing = await explainPath(fromId, toId, best);
      setLlmBriefing(briefing);
      setActiveTab('briefing');
      setStatus(`AI threat analysis complete: ${briefing.severity || briefing.threatLevel || 'HIGH'} Threat on active dataset.`);
    } catch (err) {
      setStatus(`Failed to generate briefing: ${err.message}`);
    } finally {
      setIsGeneratingBriefing(false);
    }
  }, [pathResult, fromId, toId]);

  // Live judge scenario injection
  const handleInject = async (e) => {
    e.preventDefault();
    if (!injectFrom || !injectTo || !injectType) return;
    setInjectStatus('Injecting relationship into live graph...');

    try {
      const res = await injectRelationship(injectFrom, injectTo, injectType);
      setInjectStatus(`SUCCESS! Added [${res.type}] between '${res.from}' and '${res.to}'.`);
      // Reload graph and re-run pathfind
      await loadGraph();
      runPathFind(injectFrom, injectTo);
      setTimeout(() => setShowInjectModal(false), 1500);
    } catch (err) {
      setInjectStatus(`Injection failed: ${err.message}`);
    }
  };

  // Node click handler
  const handleNodeClick = (node) => {
    setSelectedNode(node);
    if (!fromId) {
      setFromId(node.id);
    } else if (fromId && toId && fromId !== node.id) {
      // Toggle or set
      setFromId(node.id);
    }
  };

  // Edge click handler
  const handleLinkClick = (link) => {
    setSelectedLink(link);
    runRemediationOnEdge(link.id, `${link.source.id || link.source} -[${link.type}]-> ${link.target.id || link.target}`);
  };

  // Stats calculation
  const nodeCountByType = useMemo(() => {
    const counts = { User: 0, Group: 0, ServiceAccount: 0, Machine: 0 };
    for (const n of graphData.nodes) {
      if (counts[n.type] !== undefined) counts[n.type]++;
    }
    return counts;
  }, [graphData.nodes]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', width: '100vw', background: '#07090e' }}>
      {/* Top Telemetry & Brand Bar */}
      <header style={{
        height: 54,
        padding: '0 20px',
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: 'rgba(13, 17, 26, 0.95)',
        zIndex: 10,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <img src="/logo.png" alt="ZENITH" style={{ width: 32, height: 32, borderRadius: '50%' }} />
          <div>
            <div style={{ fontWeight: 800, fontSize: 16, letterSpacing: '0.08em', color: '#fff' }}>
              ZENITH <span style={{ color: 'var(--accent-cyan)', fontSize: 12, fontWeight: 500 }}>v2.0</span>
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-dim)', letterSpacing: '0.04em' }}>
              IDENTITY PRIVILEGE GRAPH & ATTACK PATH ANALYZER
            </div>
          </div>
        </div>

        {/* Demo Quick Presets */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 11, color: 'var(--text-dim)', marginRight: 4 }}>DEMO PRESETS:</span>
          {PRESETS.map((p, idx) => (
            <button
              key={idx}
              className="btn-subtle"
              onClick={() => {
                setFromId(p.from);
                setToId(p.to);
                runPathFind(p.from, p.to);
              }}
              title={p.desc}
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Actions & Stats */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button
            className="btn-primary"
            style={{ padding: '6px 12px', fontSize: 12 }}
            onClick={() => setShowInjectModal(true)}
          >
            + Live Inject Edge
          </button>
          <a
            href="/landing-page/index.html"
            target="_blank"
            rel="noreferrer"
            className="btn-subtle"
            style={{ textDecoration: 'none' }}
          >
            Landing Page
          </a>
        </div>
      </header>

      {/* Main Workspace */}
      <div style={{ display: 'flex', flex: 1, position: 'relative', overflow: 'hidden' }}>
        {/* Left Control Panel */}
        <aside style={{
          width: 380,
          background: 'var(--bg-panel)',
          borderRight: '1px solid var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          backdropFilter: 'blur(12px)',
          zIndex: 5,
        }}>
          {/* Selected Node Quick-Actions Inspector */}
          {selectedNode && (
            <div style={{
              padding: '10px 16px',
              background: '#0d1524',
              borderBottom: '1px solid var(--border-subtle)',
              display: 'flex',
              flexDirection: 'column',
              gap: 6,
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-cyan)' }}>SELECTED ENTITY</span>
                <button
                  style={{ background: 'none', border: 'none', color: 'var(--text-dim)', fontSize: 12, cursor: 'pointer' }}
                  onClick={() => setSelectedNode(null)}
                >
                  ✕
                </button>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 700, fontSize: 13, color: '#fff' }}>{selectedNode.name}</div>
                  <div style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>{selectedNode.id}</div>
                </div>
                <span style={{ fontSize: 11, color: TYPE_COLORS[selectedNode.type] || '#fff' }}>{selectedNode.type}</span>
              </div>
              <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
                <button
                  className="btn-subtle"
                  style={{ flex: 1, fontSize: 10, padding: '4px 6px' }}
                  onClick={() => setFromId(selectedNode.id)}
                >
                  Set as Source
                </button>
                <button
                  className="btn-subtle"
                  style={{ flex: 1, fontSize: 10, padding: '4px 6px' }}
                  onClick={() => setToId(selectedNode.id)}
                >
                  Set as Target
                </button>
                <button
                  className="btn-subtle"
                  style={{ flex: 1, fontSize: 10, padding: '4px 6px', color: 'var(--accent-amber)' }}
                  onClick={() => runBlastRadius(selectedNode.id)}
                >
                  Blast Radius
                </button>
              </div>
            </div>
          )}

          {/* Query Inputs Card */}
          <div style={{ padding: 16, borderBottom: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 12 }}>
              <div>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 4 }}>
                  SOURCE IDENTITY (FROM)
                </label>
                <input
                  value={fromId}
                  onChange={(e) => setFromId(e.target.value)}
                  placeholder="e.g. user-3"
                  style={{ width: '100%' }}
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 4 }}>
                  TARGET ASSET (TO)
                </label>
                <input
                  value={toId}
                  onChange={(e) => setToId(e.target.value)}
                  placeholder="e.g. grp-domain-admins"
                  style={{ width: '100%' }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8 }}>
              <button
                className="btn-primary"
                style={{ flex: 1 }}
                onClick={() => runPathFind()}
              >
                Find Attack Paths
              </button>
              <button
                className="btn-subtle"
                onClick={() => runBlastRadius()}
                title="Calculate downstream reachable nodes"
              >
                Blast Radius
              </button>
            </div>

            {/* Status Bar */}
            <div style={{
              marginTop: 10,
              padding: '6px 10px',
              borderRadius: 4,
              background: '#0a0e17',
              border: '1px solid var(--border-subtle)',
              fontSize: 11,
              color: 'var(--accent-cyan)',
              fontFamily: 'var(--font-mono)',
            }}>
              &gt; {status}
            </div>
          </div>

          {/* Tab Navigation */}
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border-subtle)', background: '#090d14' }}>
            <button
              style={{
                flex: 1,
                padding: '10px 0',
                fontSize: 11,
                fontWeight: 600,
                background: activeTab === 'paths' ? 'var(--bg-card)' : 'transparent',
                color: activeTab === 'paths' ? 'var(--accent-cyan)' : 'var(--text-muted)',
                border: 'none',
                borderBottom: activeTab === 'paths' ? '2px solid var(--accent-cyan)' : 'none',
                cursor: 'pointer',
              }}
              onClick={() => setActiveTab('paths')}
            >
              Paths {pathResult?.paths?.length ? `(${pathResult.paths.length})` : ''}
            </button>
            <button
              style={{
                flex: 1,
                padding: '10px 0',
                fontSize: 11,
                fontWeight: 600,
                background: activeTab === 'blast' ? 'var(--bg-card)' : 'transparent',
                color: activeTab === 'blast' ? 'var(--accent-amber)' : 'var(--text-muted)',
                border: 'none',
                borderBottom: activeTab === 'blast' ? '2px solid var(--accent-amber)' : 'none',
                cursor: 'pointer',
              }}
              onClick={() => setActiveTab('blast')}
            >
              Blast {blastRadiusData ? `(${blastRadiusData.reachableCount})` : ''}
            </button>
            <button
              style={{
                flex: 1,
                padding: '10px 0',
                fontSize: 11,
                fontWeight: 600,
                background: activeTab === 'calc' ? 'var(--bg-card)' : 'transparent',
                color: activeTab === 'calc' ? 'var(--accent-emerald)' : 'var(--text-muted)',
                border: 'none',
                borderBottom: activeTab === 'calc' ? '2px solid var(--accent-emerald)' : 'none',
                cursor: 'pointer',
              }}
              onClick={() => {
                setActiveTab('calc');
                syncCalcFromActivePath();
              }}
            >
              ⚡ Risk Calc
            </button>
            <button
              style={{
                flex: 1,
                padding: '10px 0',
                fontSize: 11,
                fontWeight: 600,
                background: activeTab === 'briefing' ? 'var(--bg-card)' : 'transparent',
                color: activeTab === 'briefing' ? 'var(--accent-purple)' : 'var(--text-muted)',
                border: 'none',
                borderBottom: activeTab === 'briefing' ? '2px solid var(--accent-purple)' : 'none',
                cursor: 'pointer',
              }}
              onClick={() => {
                setActiveTab('briefing');
                if (!llmBriefing && pathResult?.paths?.length) runExplainPath();
              }}
            >
              AI Intelligence
            </button>
          </div>

          {/* Panel Content Body */}
          <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
            {/* TAB 1: ATTACK PATHS */}
            {activeTab === 'paths' && (
              <div>
                {/* Remediation Status Banner */}
                {remediationState && (
                  <div style={{
                    padding: 12,
                    borderRadius: 6,
                    marginBottom: 14,
                    background: remediationState.pathEliminated
                      ? 'rgba(16, 185, 129, 0.15)'
                      : 'rgba(245, 158, 11, 0.15)',
                    border: `1px solid ${remediationState.pathEliminated ? 'rgba(16, 185, 129, 0.4)' : 'rgba(245, 158, 11, 0.4)'}`,
                  }}>
                    <div style={{ fontWeight: 700, fontSize: 13, color: remediationState.pathEliminated ? '#34d399' : '#fbbf24', marginBottom: 4 }}>
                      {remediationState.pathEliminated ? 'CHOKEPOINT NEUTRALIZED' : 'ATTACK PATH REROUTED'}
                    </div>
                    <div style={{ fontSize: 12, color: '#e2e8f0', marginBottom: 8 }}>
                      {remediationState.pathEliminated
                        ? 'Revoking this privilege broke the attack chain. No alternate route exists to target.'
                        : `Privilege revoked, but path reroutes via ${remediationState.remainingPathCount} alternate route(s). Highlighted in golden amber.`}
                    </div>
                    <button
                      className="btn-subtle"
                      style={{ fontSize: 11, width: '100%', padding: '4px 8px' }}
                      onClick={() => {
                        setRemediationState(null);
                        setReroutedLinks(new Set());
                        if (pathResult?.paths?.length > 0) {
                          const best = pathResult.paths[0];
                          setHighlightLinks(new Set(best.steps.map((s) => `${s.from}->${s.to}`)));
                          setHighlightNodes(new Set(best.steps.flatMap((s) => [s.from, s.to])));
                          setStatus(`Restored primary attack path (${best.hops} hops, Risk ${best.riskScore}/100).`);
                        }
                      }}
                    >
                      ↺ Reset Remediation Simulation
                    </button>
                  </div>
                )}

                {pathResult && pathResult.paths && pathResult.paths.length > 0 ? (
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                      <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-muted)' }}>RANKED EXPLOIT PATHS</span>
                      <button
                        className="btn-subtle"
                        style={{ fontSize: 11, padding: '4px 8px', color: 'var(--accent-purple)' }}
                        onClick={runExplainPath}
                        disabled={isGeneratingBriefing}
                      >
                        {isGeneratingBriefing ? 'ANALYZING ATTACK PATH...' : 'Explain Path (Live AI)'}
                      </button>
                    </div>

                    {pathResult.paths.map((p, pIdx) => {
                      const riskClass = p.riskScore >= 70 ? 'badge-critical' : p.riskScore >= 45 ? 'badge-high' : 'badge-medium';
                      return (
                        <div
                          key={pIdx}
                          style={{
                            background: pIdx === 0 ? 'var(--bg-card)' : '#0b0f17',
                            border: `1px solid ${pIdx === 0 ? 'var(--accent-cyan)' : 'var(--border-subtle)'}`,
                            borderRadius: 6,
                            padding: 12,
                            marginBottom: 12,
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                              <span style={{ fontWeight: 700, fontSize: 13 }}>Path #{pIdx + 1}</span>
                              <span className={`badge ${riskClass}`}>Risk {p.riskScore}/100</span>
                              <button
                                className="btn-subtle"
                                style={{ fontSize: 10, padding: '2px 6px', color: 'var(--accent-emerald)', borderColor: 'rgba(16, 185, 129, 0.3)' }}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setCalcHops(p.hops);
                                  setCalcCost(p.totalCost);
                                  setCalcTargetTier(p.target?.critical ? 'tier0' : 'tier2');
                                  setActiveTab('calc');
                                }}
                                title="Open this path parameters in the interactive Risk Calculator"
                              >
                                ⚡ Calc
                              </button>
                            </div>
                            <span style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                              {p.hops} hops • cost {p.totalCost}
                            </span>
                          </div>

                          {/* Step-by-step chain */}
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                            {p.steps.map((step, sIdx) => (
                              <div
                                key={sIdx}
                                style={{
                                  background: '#090d15',
                                  padding: '6px 8px',
                                  borderRadius: 4,
                                  fontSize: 12,
                                  display: 'flex',
                                  alignItems: 'center',
                                  justifyContent: 'space-between',
                                  borderLeft: '3px solid var(--accent-cyan)',
                                }}
                              >
                                <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  <span style={{ color: '#fff', fontWeight: 500 }}>{step.fromName}</span>
                                  <span style={{ color: 'var(--accent-amber)', margin: '0 4px', fontSize: 11 }}>
                                    --[{step.relationship}]--&gt;
                                  </span>
                                  <span style={{ color: '#fff', fontWeight: 500 }}>{step.toName}</span>
                                </div>
                                <button
                                  className="btn-danger"
                                  style={{ padding: '2px 6px', fontSize: 10, flexShrink: 0, marginLeft: 6 }}
                                  onClick={() => runRemediationOnEdge(step.relId, `${step.fromName} -[${step.relationship}]-> ${step.toName}`)}
                                  title="Simulate revoking this specific edge"
                                >
                                  Revoke
                                </button>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', padding: '30px 10px', color: 'var(--text-dim)' }}>
                    <div style={{ fontSize: 32, marginBottom: 8 }}>🛡️</div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-muted)' }}>No Attack Paths Computed</div>
                    <div style={{ fontSize: 12, marginTop: 4 }}>
                      Select a Source and Target node above and click <strong>Find Attack Paths</strong>, or choose a <strong>Demo Preset</strong>.
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* TAB 2: BLAST RADIUS */}
            {activeTab === 'blast' && (
              <div>
                {blastRadiusData ? (
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 700 }}>Blast Radius Analysis</div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Root Node: {blastRadiusData.nodeId}</div>
                      </div>
                      <button className="btn-subtle" onClick={clearBlastRadius}>Clear</button>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 14 }}>
                      <div style={{ background: 'var(--bg-card)', padding: 12, borderRadius: 6, textAlign: 'center' }}>
                        <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--accent-amber)' }}>
                          {blastRadiusData.reachableCount}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Total Reachable</div>
                      </div>
                      <div style={{ background: 'var(--bg-card)', padding: 12, borderRadius: 6, textAlign: 'center' }}>
                        <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--accent-red)' }}>
                          {blastRadiusData.reachable.filter((n) => n.critical).length}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Critical Tier-0 Assets</div>
                      </div>
                    </div>

                    <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8 }}>
                      EXPOSED DOWNSTREAM ASSETS
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 360, overflowY: 'auto' }}>
                      {blastRadiusData.reachable.map((item, idx) => (
                        <div
                          key={idx}
                          style={{
                            background: '#090d15',
                            padding: '8px 10px',
                            borderRadius: 4,
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            borderLeft: `3px solid ${item.critical ? 'var(--accent-red)' : TYPE_COLORS[item.type] || '#888'}`,
                          }}
                        >
                          <div>
                            <div style={{ fontWeight: 600, fontSize: 12 }}>{item.name}</div>
                            <div style={{ fontSize: 10, color: 'var(--text-dim)' }}>ID: {item.id}</div>
                          </div>
                          <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                            <span style={{ fontSize: 10, color: TYPE_COLORS[item.type] || '#888' }}>{item.type}</span>
                            {item.critical && <span className="badge badge-critical">Tier-0</span>}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', padding: '30px 10px', color: 'var(--text-dim)' }}>
                    <div style={{ fontSize: 32, marginBottom: 8 }}>💥</div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-muted)' }}>Blast Radius Uncalculated</div>
                    <div style={{ fontSize: 12, marginTop: 4 }}>
                      Click any node on the graph canvas or enter an ID above, then click <strong>Blast Radius</strong>.
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* TAB: RISK CALCULATOR */}
            {activeTab === 'calc' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {/* Header & Sync Controls */}
                <div style={{
                  padding: 12,
                  background: 'rgba(16, 185, 129, 0.08)',
                  border: '1px solid rgba(16, 185, 129, 0.25)',
                  borderRadius: 6,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: 13 }}>⚡</span>
                      <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent-emerald)', letterSpacing: '0.05em' }}>
                        DYNAMIC RISK CALCULATOR
                      </span>
                    </div>
                    <span style={{
                      fontSize: 10,
                      fontFamily: 'var(--font-mono)',
                      background: 'rgba(16, 185, 129, 0.15)',
                      color: 'var(--accent-emerald)',
                      padding: '2px 6px',
                      borderRadius: 4,
                      border: '1px solid rgba(16, 185, 129, 0.3)',
                    }}>
                      INTERACTIVE ENGINE
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4, marginBottom: 10 }}>
                    Simulate lateral risk scoring based on path hop distance, exploit friction cost, target asset criticality tier, and privilege surface factors.
                  </div>

                  {/* Actions & Preset Shortcuts */}
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    <button
                      onClick={syncCalcFromActivePath}
                      disabled={!pathResult?.paths?.length}
                      style={{
                        padding: '5px 10px',
                        fontSize: 11,
                        fontWeight: 600,
                        background: pathResult?.paths?.length ? 'var(--accent-cyan)' : 'var(--bg-card)',
                        color: pathResult?.paths?.length ? '#000' : 'var(--text-dim)',
                        border: 'none',
                        borderRadius: 4,
                        cursor: pathResult?.paths?.length ? 'pointer' : 'not-allowed',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 5,
                      }}
                      title={pathResult?.paths?.length ? 'Pull hops, cost, and target tier from active attack path' : 'Find an attack path first to sync'}
                    >
                      <span>🔄</span> Sync From Active Path
                    </button>
                    <button
                      onClick={() => {
                        setCalcHops(3);
                        setCalcCost(9);
                        setCalcTargetTier('tier0');
                        setCalcSurfaceFactor(5);
                      }}
                      style={{
                        padding: '5px 8px',
                        fontSize: 10,
                        fontWeight: 600,
                        background: 'rgba(255, 255, 255, 0.05)',
                        color: 'var(--text-muted)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 4,
                        cursor: 'pointer',
                      }}
                    >
                      Default Path
                    </button>
                    <button
                      onClick={() => {
                        setCalcHops(1);
                        setCalcCost(2);
                        setCalcTargetTier('tier0');
                        setCalcSurfaceFactor(10);
                      }}
                      style={{
                        padding: '5px 8px',
                        fontSize: 10,
                        fontWeight: 600,
                        background: 'rgba(239, 68, 68, 0.1)',
                        color: 'var(--accent-red)',
                        border: '1px solid rgba(239, 68, 68, 0.3)',
                        borderRadius: 4,
                        cursor: 'pointer',
                      }}
                    >
                      Direct DA (High)
                    </button>
                    <button
                      onClick={() => {
                        setCalcHops(6);
                        setCalcCost(24);
                        setCalcTargetTier('tier1');
                        setCalcSurfaceFactor(0);
                      }}
                      style={{
                        padding: '5px 8px',
                        fontSize: 10,
                        fontWeight: 600,
                        background: 'rgba(59, 130, 246, 0.1)',
                        color: 'var(--accent-blue)',
                        border: '1px solid rgba(59, 130, 246, 0.3)',
                        borderRadius: 4,
                        cursor: 'pointer',
                      }}
                    >
                      Deep Pivot (Low)
                    </button>
                  </div>
                </div>

                {/* Main Threat Score & Dynamic Gauge Card */}
                <div style={{
                  padding: 16,
                  background: 'linear-gradient(180deg, #111827 0%, #0b0f19 100%)',
                  border: `1px solid ${
                    calculatedRiskScore >= 80 ? 'var(--accent-red)' :
                    calculatedRiskScore >= 60 ? 'var(--accent-amber)' :
                    calculatedRiskScore >= 40 ? 'var(--accent-cyan)' : 'var(--accent-emerald)'
                  }`,
                  borderRadius: 8,
                  boxShadow: `0 0 25px ${
                    calculatedRiskScore >= 80 ? 'rgba(239, 68, 68, 0.15)' :
                    calculatedRiskScore >= 60 ? 'rgba(245, 158, 11, 0.15)' :
                    calculatedRiskScore >= 40 ? 'rgba(6, 182, 212, 0.15)' : 'rgba(16, 185, 129, 0.15)'
                  }`,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                    <div>
                      <div style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>
                        CALCULATED THREAT EXPOSURE
                      </div>
                      <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
                        <span style={{
                          fontSize: 40,
                          fontWeight: 900,
                          fontFamily: 'var(--font-mono)',
                          color: calculatedRiskScore >= 80 ? 'var(--accent-red)' :
                                 calculatedRiskScore >= 60 ? 'var(--accent-amber)' :
                                 calculatedRiskScore >= 40 ? 'var(--accent-cyan)' : 'var(--accent-emerald)',
                          lineHeight: 1,
                        }}>
                          {calculatedRiskScore}
                        </span>
                        <span style={{ fontSize: 18, color: 'var(--text-dim)', fontWeight: 600 }}>/ 100</span>
                      </div>
                    </div>

                    <div style={{ textAlign: 'right' }}>
                      <span style={{
                        display: 'inline-block',
                        padding: '4px 10px',
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 800,
                        letterSpacing: '0.06em',
                        background: calculatedRiskScore >= 80 ? 'rgba(239, 68, 68, 0.2)' :
                                    calculatedRiskScore >= 60 ? 'rgba(245, 158, 11, 0.2)' :
                                    calculatedRiskScore >= 40 ? 'rgba(6, 182, 212, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                        color: calculatedRiskScore >= 80 ? 'var(--accent-red)' :
                               calculatedRiskScore >= 60 ? 'var(--accent-amber)' :
                               calculatedRiskScore >= 40 ? 'var(--accent-cyan)' : 'var(--accent-emerald)',
                        border: `1px solid ${
                          calculatedRiskScore >= 80 ? 'rgba(239, 68, 68, 0.4)' :
                          calculatedRiskScore >= 60 ? 'rgba(245, 158, 11, 0.4)' :
                          calculatedRiskScore >= 40 ? 'rgba(6, 182, 212, 0.4)' : 'rgba(16, 185, 129, 0.4)'
                        }`,
                      }}>
                        {calculatedRiskScore >= 80 ? 'CRITICAL SEVERITY' :
                         calculatedRiskScore >= 60 ? 'HIGH SEVERITY' :
                         calculatedRiskScore >= 40 ? 'MEDIUM SEVERITY' : 'LOW SEVERITY'}
                      </span>
                      <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 5, fontFamily: 'var(--font-mono)' }}>
                        {calculatedRiskScore >= 80 ? 'Rapid Compromise Path' :
                         calculatedRiskScore >= 60 ? 'Plausible Lateral Path' :
                         calculatedRiskScore >= 40 ? 'Moderate Effort Required' : 'High Friction Defense'}
                      </div>
                    </div>
                  </div>

                  {/* Visual Progress Bar */}
                  <div style={{
                    width: '100%',
                    height: 8,
                    background: '#1a2234',
                    borderRadius: 4,
                    overflow: 'hidden',
                    marginBottom: 14,
                    position: 'relative',
                  }}>
                    <div style={{
                      width: `${calculatedRiskScore}%`,
                      height: '100%',
                      background: calculatedRiskScore >= 80 ? 'linear-gradient(90deg, #f59e0b, #ef4444)' :
                                  calculatedRiskScore >= 60 ? 'linear-gradient(90deg, #06b6d4, #f59e0b)' :
                                  'linear-gradient(90deg, #10b981, #06b6d4)',
                      borderRadius: 4,
                      transition: 'width 0.3s ease, background 0.3s ease',
                    }} />
                  </div>

                  {/* Telemetry Breakdown Grid */}
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: 8,
                    fontSize: 11,
                    background: '#090d15',
                    padding: 10,
                    borderRadius: 6,
                    border: '1px solid var(--border-subtle)',
                  }}>
                    <div>
                      <span style={{ color: 'var(--text-dim)', display: 'block', fontSize: 10, textTransform: 'uppercase' }}>EST. TIME-TO-COMPROMISE</span>
                      <span style={{ color: '#fff', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                        {calculatedRiskScore >= 80 ? '< 15 mins (Urgent)' :
                         calculatedRiskScore >= 60 ? '30 - 60 mins' :
                         calculatedRiskScore >= 40 ? '2 - 6 hours' : '> 24 hours'}
                      </span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-dim)', display: 'block', fontSize: 10, textTransform: 'uppercase' }}>LATERAL RESISTANCE</span>
                      <span style={{ color: '#fff', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                        {calculatedRiskScore >= 80 ? 'Minimal (Direct Session)' :
                         calculatedRiskScore >= 60 ? 'Standard Friction' :
                         'High (Multiple Hops)'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Interactive Sliders & Configuration */}
                <div style={{
                  padding: 14,
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 6,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 14,
                }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    Model Parameter Controls
                  </div>

                  {/* Target Asset Criticality */}
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: 11 }}>
                      <span style={{ color: '#fff', fontWeight: 600 }}>Target Asset Criticality Tier</span>
                      <span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        Base: {calcBase} pts
                      </span>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 6 }}>
                      {[
                        { id: 'tier0', label: 'Tier-0 Apex', desc: 'DC / DA Group', base: 100 },
                        { id: 'tier1', label: 'Tier-1 Infra', desc: 'Servers / DBs', base: 90 },
                        { id: 'tier2', label: 'Tier-2 Host', desc: 'Workstations', base: 85 },
                      ].map((tier) => (
                        <button
                          key={tier.id}
                          onClick={() => setCalcTargetTier(tier.id)}
                          style={{
                            padding: '8px 6px',
                            background: calcTargetTier === tier.id ? 'rgba(56, 189, 248, 0.15)' : '#090d15',
                            border: `1px solid ${calcTargetTier === tier.id ? 'var(--accent-cyan)' : 'var(--border-subtle)'}`,
                            borderRadius: 6,
                            color: calcTargetTier === tier.id ? 'var(--accent-cyan)' : 'var(--text-muted)',
                            cursor: 'pointer',
                            textAlign: 'center',
                          }}
                        >
                          <div style={{ fontSize: 11, fontWeight: 700 }}>{tier.label}</div>
                          <div style={{ fontSize: 9, color: 'var(--text-dim)', marginTop: 2 }}>{tier.desc}</div>
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Pivot Depth / Hops Slider */}
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 11 }}>
                      <span style={{ color: '#fff', fontWeight: 600 }}>Lateral Pivot Depth (Hops)</span>
                      <span style={{ color: 'var(--accent-amber)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                        {calcHops} {calcHops === 1 ? 'Hop' : 'Hops'} (Deduction: -{(calcHops * 2.5).toFixed(1)} pts)
                      </span>
                    </div>
                    <input
                      type="range"
                      min={1}
                      max={8}
                      step={1}
                      value={calcHops}
                      onChange={(e) => setCalcHops(Number(e.target.value))}
                      style={{
                        width: '100%',
                        accentColor: 'var(--accent-amber)',
                        cursor: 'pointer',
                      }}
                    />
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: 'var(--text-dim)', marginTop: 2 }}>
                      <span>1 Hop (Direct)</span>
                      <span>4 Hops (Standard Pivot)</span>
                      <span>8 Hops (Deep Chain)</span>
                    </div>
                  </div>

                  {/* Exploit Friction Cost Slider */}
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 11 }}>
                      <span style={{ color: '#fff', fontWeight: 600 }}>Exploit Difficulty Cost (Total Weight)</span>
                      <span style={{ color: 'var(--accent-red)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                        Cost {calcCost} (Deduction: -{(calcCost * 3.5).toFixed(1)} pts)
                      </span>
                    </div>
                    <input
                      type="range"
                      min={1}
                      max={35}
                      step={1}
                      value={calcCost}
                      onChange={(e) => setCalcCost(Number(e.target.value))}
                      style={{
                        width: '100%',
                        accentColor: 'var(--accent-red)',
                        cursor: 'pointer',
                      }}
                    />
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: 'var(--text-dim)', marginTop: 2 }}>
                      <span>1 (Effortless)</span>
                      <span>18 (Moderate MFA/Kerberoast)</span>
                      <span>35 (Maximum Friction)</span>
                    </div>
                  </div>

                  {/* Privilege Attack Surface Factor */}
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: 11 }}>
                      <span style={{ color: '#fff', fontWeight: 600 }}>Privilege Attack Surface Factor</span>
                      <span style={{
                        color: calcSurfaceFactor > 0 ? 'var(--accent-red)' : calcSurfaceFactor < 0 ? 'var(--accent-emerald)' : 'var(--text-dim)',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                      }}>
                        {calcSurfaceFactor > 0 ? `+${calcSurfaceFactor}` : calcSurfaceFactor} pts
                      </span>
                    </div>
                    <select
                      value={calcSurfaceFactor}
                      onChange={(e) => setCalcSurfaceFactor(Number(e.target.value))}
                      style={{
                        width: '100%',
                        padding: '8px 10px',
                        background: '#090d15',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 6,
                        color: '#fff',
                        fontSize: 12,
                        cursor: 'pointer',
                      }}
                    >
                      <option value={10}>+10 pts — High Abuse (Active LSASS Session / ResetPassword DACL)</option>
                      <option value={5}>+5 pts — Moderate Abuse (Cached Kerberos / DCOM Access)</option>
                      <option value={0}>+0 pts — Standard Lateral Vector</option>
                      <option value={-10}>-10 pts — Hardened (Credential Guard / LAPS Active)</option>
                    </select>
                  </div>
                </div>

                {/* Mathematical Formula Breakdown */}
                <div style={{
                  padding: 12,
                  background: '#090d15',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 6,
                  fontFamily: 'var(--font-mono)',
                  fontSize: 11,
                }}>
                  <div style={{ color: 'var(--text-dim)', fontSize: 10, textTransform: 'uppercase', marginBottom: 6 }}>
                    ARITHMETIC FORMULA BREAKDOWN
                  </div>
                  <div style={{ color: 'var(--accent-cyan)', background: '#05070a', padding: 8, borderRadius: 4, lineHeight: 1.5, wordBreak: 'break-all' }}>
                    Score = clamp(5, 100, Base ({calcBase}) - Friction ({(calcCost * 3.5).toFixed(1)}) - Hops ({(calcHops * 2.5).toFixed(1)}) + Surface ({calcSurfaceFactor >= 0 ? `+${calcSurfaceFactor}` : calcSurfaceFactor})) = <strong style={{ color: '#fff' }}>{calculatedRiskScore}</strong>
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 8, lineHeight: 1.4 }}>
                    • <strong>Friction Penalty:</strong> Each Dijkstra edge weight adds exploit resistance (-3.5 pts/weight).<br />
                    • <strong>Hop Penalty:</strong> Each lateral pivot increases probability of detection (-2.5 pts/hop).<br />
                    • <strong>Criticality Baseline:</strong> Tier-0 Apex targets start at 100 baseline vulnerability.
                  </div>
                </div>

                {/* Chokepoint Remediation Simulation Preview */}
                {pathResult?.paths?.[0] && (
                  <div style={{
                    padding: 12,
                    background: 'rgba(59, 130, 246, 0.08)',
                    border: '1px solid rgba(59, 130, 246, 0.25)',
                    borderRadius: 6,
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                      <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-blue)', textTransform: 'uppercase' }}>
                        🛡️ Remediation Impact Simulator
                      </span>
                      <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--accent-emerald)' }}>
                        Est. Risk Reduction: -{Math.min(calculatedRiskScore - 15, 45)} pts
                      </span>
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, lineHeight: 1.4 }}>
                      Revoking the primary chokepoint in the active path (<strong>{pathResult.paths[0].steps[0]?.fromName} -[{pathResult.paths[0].steps[0]?.relationship}]-&gt; {pathResult.paths[0].steps[0]?.toName}</strong>) severs this lateral vector.
                    </div>
                    <button
                      className="btn-danger"
                      style={{ width: '100%', padding: '6px 12px', fontSize: 11, fontWeight: 600 }}
                      onClick={() => {
                        const step = pathResult.paths[0].steps[0];
                        if (step) {
                          runRemediationOnEdge(step.relId, `${step.fromName} -[${step.relationship}]-> ${step.toName}`);
                          setActiveTab('paths');
                        }
                      }}
                    >
                      🛡️ Simulate Severing Chokepoint in Graph
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* TAB 3: LIVE AI REASONING */}
            {activeTab === 'briefing' && (
              <div>
                {/* Live AI Status Bar */}
                {isGeneratingBriefing ? (
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 12px',
                    background: 'rgba(56, 189, 248, 0.1)',
                    border: '1px solid rgba(56, 189, 248, 0.35)',
                    borderRadius: 6,
                    marginBottom: 14,
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--accent-cyan)', fontSize: 11, fontWeight: 700, letterSpacing: '0.05em' }}>
                      <span className="live-pulse-dot" style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent-cyan)', display: 'inline-block' }} />
                      ANALYZING DATASET ATTACK PATH...
                    </div>
                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>ZENITH Cyber AI</span>
                  </div>
                ) : llmBriefing ? (
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 12px',
                    background: 'rgba(16, 185, 129, 0.1)',
                    border: '1px solid rgba(16, 185, 129, 0.35)',
                    borderRadius: 6,
                    marginBottom: 14,
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{
                        width: 8,
                        height: 8,
                        borderRadius: '50%',
                        background: '#10b981',
                        boxShadow: '0 0 8px #10b981',
                        display: 'inline-block',
                      }} />
                      <span style={{
                        fontSize: 11,
                        fontWeight: 800,
                        letterSpacing: '0.05em',
                        color: '#34d399',
                      }}>
                        ● AI THREAT ANALYSIS COMPLETE
                      </span>
                    </div>
                    <span className="badge" style={{
                      fontSize: 10,
                      background: 'rgba(56, 189, 248, 0.12)',
                      color: 'var(--accent-cyan)',
                      border: '1px solid rgba(56, 189, 248, 0.25)',
                    }}>
                      {llmBriefing.model || 'Active Directory Dataset Model'}
                    </span>
                  </div>
                ) : (
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 12px',
                    background: 'rgba(6, 182, 212, 0.08)',
                    border: '1px solid rgba(6, 182, 212, 0.25)',
                    borderRadius: 6,
                    marginBottom: 14,
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--accent-cyan)', fontSize: 11, fontWeight: 700, letterSpacing: '0.05em' }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent-cyan)', display: 'inline-block' }} />
                      ● LIVE AI THREAT INTELLIGENCE
                    </div>
                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>Neo4j Verified Dataset</span>
                  </div>
                )}

                {llmBriefing ? (
                  <div style={{ fontSize: 12, lineHeight: 1.5 }}>
                    {/* Severity, Risk & Actions Strip */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, flexWrap: 'wrap', gap: 8 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span className={`badge ${
                          (llmBriefing.severity || llmBriefing.threatLevel) === 'CRITICAL' ? 'badge-critical' :
                          (llmBriefing.severity || llmBriefing.threatLevel) === 'HIGH' ? 'badge-high' :
                          (llmBriefing.severity || llmBriefing.threatLevel) === 'MEDIUM' ? 'badge-medium' : 'badge-low'
                        }`}>
                          {(llmBriefing.severity || llmBriefing.threatLevel)} SEVERITY
                        </span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent-cyan)' }}>
                          Risk Score: {llmBriefing.riskScore || llmBriefing.requestPayload?.path?.riskScore}/100
                        </span>
                      </div>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button
                          className="btn-subtle"
                          style={{ fontSize: 11, padding: '3px 8px', color: 'var(--accent-emerald)', borderColor: 'rgba(16, 185, 129, 0.3)' }}
                          onClick={() => {
                            if (llmBriefing.requestPayload?.path) {
                              setCalcHops(llmBriefing.requestPayload.path.hops);
                              setCalcCost(llmBriefing.requestPayload.path.totalCost);
                              setCalcTargetTier(llmBriefing.requestPayload.target?.critical ? 'tier0' : 'tier2');
                            }
                            setActiveTab('calc');
                          }}
                        >
                          ⚡ Test in Calculator
                        </button>
                        <button
                          className="btn-subtle"
                          style={{ fontSize: 11, padding: '3px 8px', display: 'flex', alignItems: 'center', gap: 4 }}
                          onClick={runExplainPath}
                          disabled={isGeneratingBriefing}
                        >
                          🔄 Re-run
                        </button>
                      </div>
                    </div>

                    {/* Executive Summary */}
                    <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6, color: '#fff' }}>EXECUTIVE SUMMARY</div>
                    <p style={{ color: '#cbd5e1', marginBottom: 14, background: '#0a0f19', padding: 10, borderRadius: 6, border: '1px solid var(--border-subtle)', lineHeight: 1.6 }}>
                      {llmBriefing.executiveSummary}
                    </p>

                    {/* Attack Narrative */}
                    {llmBriefing.attackNarrative && (
                      <div style={{ marginBottom: 14 }}>
                        <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6, color: '#fff' }}>ATTACK NARRATIVE</div>
                        <div style={{ color: '#94a3b8', background: 'var(--bg-card)', padding: 10, borderRadius: 6, border: '1px solid var(--border-subtle)', fontSize: 11, lineHeight: 1.6 }}>
                          {llmBriefing.attackNarrative}
                        </div>
                      </div>
                    )}

                    {/* Primary Chokepoint */}
                    {llmBriefing.primaryChokepoint && (
                      <div style={{ marginBottom: 14 }}>
                        <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6, color: '#fff' }}>PRIMARY CHOKEPOINT</div>
                        <div style={{
                          background: 'rgba(239, 68, 68, 0.08)',
                          border: '1px solid rgba(239, 68, 68, 0.3)',
                          borderRadius: 6,
                          padding: 10,
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                            <span className="badge badge-critical" style={{ fontSize: 10 }}>
                              Pivot Vector: {llmBriefing.primaryChokepoint.relationship}
                            </span>
                            {pathResult?.paths?.[0]?.steps?.find((s) => s.relationship === llmBriefing.primaryChokepoint.relationship) && (
                              <button
                                className="btn-subtle"
                                style={{ fontSize: 10, padding: '2px 8px', color: '#f87171', borderColor: 'rgba(239, 68, 68, 0.4)' }}
                                onClick={() => {
                                  const step = pathResult.paths[0].steps.find((s) => s.relationship === llmBriefing.primaryChokepoint.relationship);
                                  if (step) runRemediationOnEdge(step.relId, `${step.from} -[${step.relationship}]-> ${step.to}`);
                                }}
                              >
                                Revoke Chokepoint Edge
                              </button>
                            )}
                          </div>
                          <div style={{ color: '#e2e8f0', fontSize: 11, lineHeight: 1.5 }}>
                            {llmBriefing.primaryChokepoint.reason}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Verified Facts from Graph */}
                    {llmBriefing.verifiedFacts && llmBriefing.verifiedFacts.length > 0 && (
                      <div style={{ marginBottom: 14 }}>
                        <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6, color: '#fff' }}>VERIFIED GRAPH FACTS</div>
                        <ul style={{ paddingLeft: 16, color: '#94a3b8', fontSize: 11, display: 'flex', flexDirection: 'column', gap: 4 }}>
                          {llmBriefing.verifiedFacts.map((fact, idx) => (
                            <li key={idx} style={{ color: '#cbd5e1' }}>{fact}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Step-by-Step MITRE ATT&CK Analysis */}
                    <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6, color: '#fff' }}>STEP ANALYSIS (MITRE ATT&CK)</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 14 }}>
                      {(llmBriefing.stepAnalysis || []).map((item, idx) => (
                        <div key={idx} style={{ background: 'var(--bg-card)', padding: 10, borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4, flexWrap: 'wrap', gap: 4 }}>
                            <span style={{ fontWeight: 600, color: 'var(--accent-amber)', fontSize: 11 }}>
                              Hop {idx + 1}: [{item.relationship}]
                            </span>
                            <span className="badge badge-medium" style={{ fontSize: 10 }}>{item.mitreTechnique}</span>
                          </div>
                          <div style={{ color: '#e2e8f0', fontSize: 11, lineHeight: 1.5 }}>{item.explanation}</div>
                        </div>
                      ))}
                    </div>

                    {/* Detection Opportunities */}
                    {llmBriefing.detectionOpportunities && llmBriefing.detectionOpportunities.length > 0 && (
                      <div style={{ marginBottom: 14 }}>
                        <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6, color: '#fff' }}>DETECTION OPPORTUNITIES</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                          {llmBriefing.detectionOpportunities.map((det, idx) => (
                            <div key={idx} style={{ background: '#0a0e17', padding: '8px 10px', borderRadius: 6, border: '1px solid var(--border-subtle)', fontSize: 11, color: '#38bdf8' }}>
                              <strong style={{ color: '#fff' }}>Vector {idx + 1}:</strong> {det}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Recommendations */}
                    <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6, color: '#fff' }}>REMEDIATION PLAYBOOK</div>
                    <ul style={{ paddingLeft: 16, color: '#94a3b8', fontSize: 11, display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 14 }}>
                      {(llmBriefing.recommendations || llmBriefing.remediationPlaybook || []).map((rule, idx) => (
                        <li key={idx} style={{ color: '#cbd5e1' }}>{rule}</li>
                      ))}
                    </ul>

                    {/* Graph Reasoning & Threat Model Rationale */}
                    {llmBriefing.reasoning && (
                      <div style={{ marginBottom: 14 }}>
                        <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6, color: '#fff' }}>AI GRAPH REASONING</div>
                        <div style={{ color: '#94a3b8', background: '#0d131f', padding: 10, borderRadius: 6, border: '1px solid rgba(59, 130, 246, 0.2)', fontSize: 11, lineHeight: 1.6 }}>
                          {llmBriefing.reasoning}
                        </div>
                      </div>
                    )}

                    {/* Inspect API Payload Accordion */}
                    <details style={{ background: '#07090e', border: '1px solid var(--border-subtle)', borderRadius: 6, padding: '8px 10px', fontSize: 11, marginBottom: 10 }}>
                      <summary style={{ cursor: 'pointer', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                        Inspect Live API Request Payload
                      </summary>
                      <pre style={{
                        marginTop: 8,
                        padding: 8,
                        background: '#04060a',
                        borderRadius: 4,
                        fontSize: 10,
                        fontFamily: 'var(--font-mono)',
                        color: '#a5b4fc',
                        overflowX: 'auto',
                        maxHeight: 200,
                      }}>
                        {JSON.stringify(llmBriefing.requestPayload || llmBriefing.payload || {}, null, 2)}
                      </pre>
                    </details>
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', padding: '30px 10px', color: 'var(--text-dim)' }}>
                    <div style={{ fontSize: 32, marginBottom: 8 }}>⚡</div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-muted)' }}>Live Threat Reasoning Ready</div>
                    <div style={{ fontSize: 12, marginTop: 4, marginBottom: 16 }}>
                      Analyze the active attack path using NVIDIA NIM or deterministic graph intelligence.
                    </div>
                    <button className="btn-primary" onClick={runExplainPath} disabled={isGeneratingBriefing}>
                      {isGeneratingBriefing ? 'ANALYZING ATTACK PATH...' : 'Explain Current Attack Path'}
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Graph Legend & Telemetry Footer */}
          <div style={{ padding: 12, borderTop: '1px solid var(--border-subtle)', background: '#090d14', fontSize: 11 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
              {Object.entries(TYPE_COLORS).map(([type, color]) => (
                <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={{ width: 8, height: 8, background: color, borderRadius: '50%' }} />
                  <span style={{ color: 'var(--text-muted)' }}>{type}</span>
                  <span style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>({nodeCountByType[type] || 0})</span>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-dim)', fontSize: 10 }}>
              <span>Click node: select/fill</span>
              <span>Click edge: simulate revoke</span>
            </div>
          </div>
        </aside>

        {/* Center Force Graph Canvas */}
        <div style={{ flex: 1, position: 'relative', background: '#07090e' }}>
          <ForceGraph2D
            ref={fgRef}
            graphData={graphData}
            nodeId="id"
            nodeLabel={(n) => `${n.name} (${n.type})${n.critical ? ' [TIER-0 CRITICAL]' : ''}`}
            linkLabel={(l) => `${l.type} (Exploit Difficulty Cost: ${l.weight || 2})`}
            nodeColor={(n) => {
              if (highlightNodes.has(n.id)) return '#ef4444'; // Red for primary path
              if (blastNodes.has(n.id)) return '#f59e0b';    // Amber for blast radius
              if (n.critical) return '#dc2626';             // Dark red for critical
              return TYPE_COLORS[n.type] || '#888';
            }}
            nodeRelSize={6}
            nodeCanvasObjectMode={() => 'after'}
            nodeCanvasObject={(node, ctx, globalScale) => {
              const label = node.name || node.id;
              const isHighlighted = highlightNodes.has(node.id) || blastNodes.has(node.id);
              const fontSize = isHighlighted ? 12 / globalScale : 9 / globalScale;
              ctx.font = `${fontSize}px Inter, sans-serif`;
              ctx.textAlign = 'center';
              ctx.textBaseline = 'middle';
              ctx.fillStyle = isHighlighted ? '#ffffff' : 'rgba(255, 255, 255, 0.6)';
              ctx.fillText(label, node.x, node.y + (node.critical ? 12 : 9));

              // Pulsing ring for critical nodes
              if (node.critical) {
                ctx.beginPath();
                ctx.arc(node.x, node.y, 9, 0, 2 * Math.PI, false);
                ctx.strokeStyle = 'rgba(239, 68, 68, 0.6)';
                ctx.lineWidth = 1.5 / globalScale;
                ctx.stroke();
              }
            }}
            linkColor={(l) => {
              const key = `${l.source.id || l.source}->${l.target.id || l.target}`;
              if (highlightLinks.has(key)) return '#ef4444';       // Neon red for primary path
              if (reroutedLinks.has(key)) return '#f59e0b';       // Golden amber for rerouted path
              if (blastNodes.size > 0 && blastNodes.has(l.source.id || l.source) && blastNodes.has(l.target.id || l.target)) {
                return 'rgba(245, 158, 11, 0.45)';               // Amber for blast cascade links
              }
              return 'rgba(160, 175, 200, 0.42)';                 // Clearly visible crisp thin lines for demo presentation
            }}
            linkWidth={(l) => {
              const key = `${l.source.id || l.source}->${l.target.id || l.target}`;
              if (highlightLinks.has(key)) return 3.5;
              if (reroutedLinks.has(key)) return 3.0;
              if (blastNodes.size > 0 && blastNodes.has(l.source.id || l.source) && blastNodes.has(l.target.id || l.target)) {
                return 1.6;
              }
              return 1.1;
            }}
            linkDirectionalArrowLength={(l) => {
              const key = `${l.source.id || l.source}->${l.target.id || l.target}`;
              if (highlightLinks.has(key) || reroutedLinks.has(key)) return 5.0;
              return 3.5;
            }}
            linkDirectionalArrowRelPos={0.92}
            linkDirectionalArrowColor={(l) => {
              const key = `${l.source.id || l.source}->${l.target.id || l.target}`;
              if (highlightLinks.has(key)) return '#ef4444';
              if (reroutedLinks.has(key)) return '#f59e0b';
              return 'rgba(160, 175, 200, 0.48)';
            }}
            linkDirectionalParticles={(l) => {
              const key = `${l.source.id || l.source}->${l.target.id || l.target}`;
              if (highlightLinks.has(key)) return 4;
              if (reroutedLinks.has(key)) return 3;
              return 0;
            }}
            linkDirectionalParticleSpeed={(l) => {
              const key = `${l.source.id || l.source}->${l.target.id || l.target}`;
              return highlightLinks.has(key) ? 0.008 : 0.004;
            }}
            onNodeClick={handleNodeClick}
            onLinkClick={handleLinkClick}
            backgroundColor="#07090e"
          />

          {/* Canvas Floating Controls */}
          <div style={{ position: 'absolute', bottom: 20, right: 20, display: 'flex', gap: 8 }}>
            <button
              className="btn-subtle"
              onClick={() => fgRef.current && fgRef.current.zoomToFit(400, 30)}
              title="Reset Zoom"
            >
              Zoom to Fit
            </button>
          </div>
        </div>
      </div>

      {/* Live Scenario Injection Modal (Phase 6) */}
      {showInjectModal && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          display: 'grid',
          placeItems: 'center',
          zIndex: 100,
          backdropFilter: 'blur(6px)',
        }}>
          <div style={{
            width: 440,
            background: 'var(--bg-card)',
            border: '1px solid var(--border-active)',
            borderRadius: 8,
            padding: 24,
            boxShadow: '0 10px 40px rgba(0, 0, 0, 0.6)',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div style={{ fontWeight: 700, fontSize: 16, color: '#fff' }}>Live Scenario Privilege Injection</div>
              <button
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: 18, cursor: 'pointer' }}
                onClick={() => setShowInjectModal(false)}
              >
                ✕
              </button>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
              Inject a new privilege edge directly into the Neo4j database live to demonstrate real-time graph reasoning.
            </p>

            <form onSubmit={handleInject}>
              <div style={{ marginBottom: 12 }}>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 4 }}>
                  SOURCE IDENTITY ID
                </label>
                <input
                  value={injectFrom}
                  onChange={(e) => setInjectFrom(e.target.value)}
                  placeholder="e.g. user-50"
                  style={{ width: '100%' }}
                  required
                />
              </div>

              <div style={{ marginBottom: 12 }}>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 4 }}>
                  TARGET ASSET ID
                </label>
                <input
                  value={injectTo}
                  onChange={(e) => setInjectTo(e.target.value)}
                  placeholder="e.g. machine-5 or grp-domain-admins"
                  style={{ width: '100%' }}
                  required
                />
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 4 }}>
                  PRIVILEGE RELATIONSHIP TYPE
                </label>
                <select
                  value={injectType}
                  onChange={(e) => setInjectType(e.target.value)}
                  style={{ width: '100%' }}
                >
                  {Object.entries(relationshipTypes).map(([key, val]) => (
                    <option key={key} value={val.label}>
                      {val.label} (Weight: {val.weight}) — {val.desc}
                    </option>
                  ))}
                  {Object.keys(relationshipTypes).length === 0 && (
                    <>
                      <option value="CanRDP">CanRDP (Weight: 3)</option>
                      <option value="AdminTo">AdminTo (Weight: 2)</option>
                      <option value="HasSession">HasSession (Weight: 2)</option>
                      <option value="GenericAll">GenericAll (Weight: 1)</option>
                      <option value="Kerberoastable">Kerberoastable (Weight: 2)</option>
                      <option value="GPOAppliedTo">GPOAppliedTo (Weight: 3)</option>
                    </>
                  )}
                </select>
              </div>

              {injectStatus && (
                <div style={{ fontSize: 12, marginBottom: 12, color: injectStatus.startsWith('SUCCESS') ? '#34d399' : 'var(--accent-amber)' }}>
                  {injectStatus}
                </div>
              )}

              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button type="button" className="btn-subtle" onClick={() => setShowInjectModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  Inject Relationship Live
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
