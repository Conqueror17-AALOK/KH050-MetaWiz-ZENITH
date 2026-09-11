# ZENITH — Attack Path & Identity Privilege Graph Analyzer

> **Kurukshetra 2.0 Hackathon | Domain 2: Cybersecurity & Blockchain (Expert Tier)**  
> *Deterministic Graph Intelligence for Multi-Hop Active Directory & Cloud IAM Attack Paths*

---

## Overview

**ZENITH** is an enterprise-grade identity privilege graph and attack path analyzer inspired by SpecterOps BloodHound. It models organizational identities (users, groups, service accounts, machines) as a directed property graph in **Neo4j** and uses real **Cypher graph algorithms** to mathematically discover, cost-weight, and remediate dangerous multi-hop privilege escalation routes.

ZENITH strictly adheres to the principle of **deterministic mathematical path calculation**—reserving LLM capabilities exclusively for threat narration and executive security briefings *after* paths have been proven mathematically.

---

## Key Capabilities

1. **Deterministic Path Traversal**: Computes cheapest/shortest attack paths using Cypher `MATCH p = (start)-[*1..N]->(end)` with exploit difficulty weights.
2. **Exploit-Weighted Cost Model**: Weights relationships from 1 (trivial/silent) to 10 (high-friction/noisy).
3. **Interactive Chokepoint Remediation**: Simulates revoking individual privileges and verifies whether attack paths are eliminated or rerouted.
4. **Blast Radius Analysis**: Quantifies downstream blast radius and critical asset exposure upon identity compromise.
5. **Decoupled Threat Narration**: Generates MITRE ATT&CK mapped executive security briefings from mathematical path steps.
6. **Production Landing Page**: Cinematic gateway featuring ambient video telemetry and animated metrics.

---

## Repository Structure

```
ZENITH/
├── CONTEXT.md                    # Complete project context, architecture, & technical specification
├── README.md                     # Root project documentation
├── landing-page/                 # Cinematic ZENITH brand landing page
│   ├── index.html
│   ├── styles.css
│   ├── main.js
│   └── assets/logo.webp          # ZENITH brand mark
└── ps17-attack-path 2/           # Core application
    ├── backend/                  # Node.js + Express API & Neo4j Bolt driver
    │   ├── config/               # Database connection and relationship taxonomy
    │   ├── routes/               # API routes (/graph, /paths, /blast-radius, /simulate-remediation)
    │   ├── services/             # Graph service running Cypher queries
    │   └── scripts/seedData.js   # Enterprise synthetic identity graph generator
    └── frontend/                 # React 18 + Vite interactive force-directed graph console
        └── src/                  # GraphView canvas, path inspection panel, remediation UI
```

---

## Quick Start

### 1. Prerequisites
- **Node.js**: v18+ (`node -v`)
- **Neo4j**: v5+ or Neo4j Aura (`bolt://localhost:7687`)

### 2. Configure Backend
```bash
cd "ps17-attack-path 2/backend"
cp .env.example .env
# Configure your NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
npm install
npm run seed      # Seeds the graph with enterprise identities & planted attack paths
npm start         # Starts the API server on http://localhost:4000
```

### 3. Launch Frontend Console
```bash
cd "../frontend"
npm install
npm run dev        # Launches the interactive console on http://localhost:5173
```

### 4. View Landing Page
Open `landing-page/index.html` in any browser.

---

## Detailed Documentation
For comprehensive details on graph theory, Cypher queries, MITRE ATT&CK taxonomy, scoring formulas, and demo scripts, refer to **[CONTEXT.md](./CONTEXT.md)**.
