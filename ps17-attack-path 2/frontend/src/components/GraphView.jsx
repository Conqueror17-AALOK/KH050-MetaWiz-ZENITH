import React, { useEffect, useRef, useState, useCallback } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { getGraph, getPaths, simulateRemediation } from '../api';

const TYPE_COLORS = {
  User: '#3B8BD4',
  Group: '#EF9F27',
  ServiceAccount: '#D4537E',
  Machine: '#5DCAA5',
};

export default function GraphView() {
  const fgRef = useRef();
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [fromId, setFromId] = useState('');
  const [toId, setToId] = useState('grp-domain-admins');
  const [pathResult, setPathResult] = useState(null);
  const [highlightLinks, setHighlightLinks] = useState(new Set());
  const [highlightNodes, setHighlightNodes] = useState(new Set());
  const [status, setStatus] = useState('Loading graph...');

  useEffect(() => {
    getGraph()
      .then((data) => {
        setGraphData(data);
        setStatus(`Loaded ${data.nodes.length} nodes, ${data.links.length} edges`);
      })
      .catch((err) => setStatus(`Failed to load graph: ${err.message}`));
  }, []);

  const runPathFind = useCallback(async () => {
    if (!fromId || !toId) return;
    setStatus('Finding attack paths...');
    try {
      const result = await getPaths(fromId, toId);
      setPathResult(result);
      if (result.paths.length > 0) {
        const best = result.paths[0];
        const linkKeys = new Set(
          best.steps.map((s) => `${s.from}->${s.to}`)
        );
        const nodeKeys = new Set(best.steps.flatMap((s) => [s.from, s.to]));
        setHighlightLinks(linkKeys);
        setHighlightNodes(nodeKeys);
        setStatus(`Found ${result.paths.length} path(s). Cheapest: ${best.hops} hops, risk ${best.riskScore}/100`);
      } else {
        setHighlightLinks(new Set());
        setHighlightNodes(new Set());
        setStatus('No path found between these nodes.');
      }
    } catch (err) {
      setStatus(`Error: ${err.message}`);
    }
  }, [fromId, toId]);

  const runRemediation = useCallback(async (relId) => {
    setStatus('Simulating remediation...');
    try {
      const result = await simulateRemediation(fromId, toId, relId);
      setStatus(
        result.pathEliminated
          ? 'Path eliminated - this edge was the chokepoint.'
          : `Path still exists via ${result.remainingPathCount} other route(s).`
      );
    } catch (err) {
      setStatus(`Error: ${err.message}`);
    }
  }, [fromId, toId]);

  return (
    <div style={{ display: 'flex', height: '100vh' }}>
      <div style={{ width: 320, padding: 16, borderRight: '1px solid #30363d', overflowY: 'auto' }}>
        <h3 style={{ marginTop: 0 }}>PS17 - Attack path analyzer</h3>

        <label style={{ display: 'block', marginTop: 12, fontSize: 13 }}>From (node id)</label>
        <input
          value={fromId}
          onChange={(e) => setFromId(e.target.value)}
          placeholder="e.g. user-3"
          style={{ width: '100%', padding: 6 }}
        />

        <label style={{ display: 'block', marginTop: 12, fontSize: 13 }}>To (node id)</label>
        <input
          value={toId}
          onChange={(e) => setToId(e.target.value)}
          style={{ width: '100%', padding: 6 }}
        />

        <button onClick={runPathFind} style={{ marginTop: 12, width: '100%', padding: 8 }}>
          Find attack paths
        </button>

        <p style={{ fontSize: 12, color: '#8b949e', marginTop: 12 }}>{status}</p>

        {pathResult && pathResult.paths.length > 0 && (
          <div style={{ marginTop: 16 }}>
            <h4>Cheapest path</h4>
            <ol style={{ fontSize: 12, paddingLeft: 18 }}>
              {pathResult.paths[0].steps.map((s, i) => (
                <li key={i}>
                  {s.fromName} --[{s.relationship}]--&gt; {s.toName}
                </li>
              ))}
            </ol>
            <button
              onClick={() => runRemediation(pathResult.paths[0].steps[0].relId)}
              style={{ width: '100%', padding: 8, marginTop: 8 }}
            >
              Simulate: revoke first edge
            </button>
          </div>
        )}

        <div style={{ marginTop: 16, fontSize: 12 }}>
          <strong>Legend</strong>
          {Object.entries(TYPE_COLORS).map(([type, color]) => (
            <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
              <span style={{ width: 10, height: 10, background: color, borderRadius: '50%' }} />
              {type}
            </div>
          ))}
        </div>
      </div>

      <div style={{ flex: 1 }}>
        <ForceGraph2D
          ref={fgRef}
          graphData={graphData}
          nodeId="id"
          nodeLabel={(n) => `${n.type}: ${n.name}`}
          nodeColor={(n) =>
            highlightNodes.has(n.id) ? '#E24B4A' : TYPE_COLORS[n.type] || '#888'
          }
          nodeRelSize={5}
          linkColor={(l) =>
            highlightLinks.has(`${l.source.id || l.source}->${l.target.id || l.target}`)
              ? '#E24B4A'
              : 'rgba(255,255,255,0.15)'
          }
          linkWidth={(l) =>
            highlightLinks.has(`${l.source.id || l.source}->${l.target.id || l.target}`) ? 3 : 1
          }
          linkDirectionalArrowLength={4}
          onNodeClick={(n) => setFromId(n.id)}
          backgroundColor="#0d1117"
        />
      </div>
    </div>
  );
}
