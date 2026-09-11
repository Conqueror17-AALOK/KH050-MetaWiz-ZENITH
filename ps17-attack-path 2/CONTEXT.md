# ZENITH — Attack Path & Identity Privilege Graph Analyzer
## Complete Project Context & Technical Architecture Specification

```
   ███████╗███████╗███╗   ██╗██╗████████╗██╗  ██╗
   ╚══███╔╝██╔════╝████╗  ██║██║╚══██╔══╝██║  ██║
     ███╔╝ █████╗  ██╔██╗ ██║██║   ██║   ███████║
    ███╔╝  ██╔══╝  ██║╚██╗██║██║   ██║   ██╔══██║
   ███████╗███████╗██║ ╚████║██║   ██║   ██║  ██║
   ╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝  ╚═╝
   Identity Privilege Graph & Attack Path Intelligence
```

---

## 1. Executive Summary

- **Product Name**: **ZENITH**
- **Problem Statement**: PS17 — Attack Path & Identity Privilege Graph Analyzer
- **Competition**: Kurukshetra 2.0 (National Level Hackathon)
- **Domain**: Domain 2 — Cybersecurity & Blockchain
- **Difficulty Tier**: Expert
- **Target Audience / Users**: Red Teams, Penetration Testers, Blue Teams, Identity & Access Management (IAM) Architects, Chief Information Security Officers (CISOs).
- **Core Value Proposition**: Deterministic graph-theoretic discovery of multi-hop Active Directory (AD) and Cloud IAM identity attack paths. ZENITH exposes dangerous privilege escalation chains mathematically using real graph algorithms (Neo4j Cypher shortest-path traversals) rather than probabilistic LLM guesswork, allowing organizations to remediate chokepoints before adversaries can exploit them.

---

## 2. Problem Domain & Threat Modeling Context

### 2.1 The Problem
In modern enterprise networks (Active Directory, Azure AD/Entra ID, AWS IAM), **no single permission looks dangerous in isolation**:
- A junior helpdesk technician has permission to RDP into a developer workstation.
- That workstation has an active LSASS cached credential session from a backup service account.
- That service account has `ResetPassword` rights over a delegated OU group.
- That delegated OU group has `AdminTo` permissions on the Primary Domain Controller.

Individually, all four permissions pass standard least-privilege compliance audits. Chained together, they create a **deterministic, catastrophic attack path** that allows an attacker with low-level access to achieve full Domain Admin compromise.

### 2.2 BloodHound Lineage & ZENITH's Evolution
ZENITH draws direct inspiration from **SpecterOps BloodHound** (the global standard for Active Directory attack path discovery), while providing:
1. **Generalized Graph Modeling**: Unifies on-prem Active Directory objects with cloud IAM relationships, service principals, and cross-machine trusts.
2. **Exploit Difficulty Weighted Cost**: Unlike unweighted hop counting, ZENITH assigns empirical exploit-difficulty weights to each relationship (e.g., executing remote code via DCOM has higher operational noise/difficulty than abusing direct group membership).
3. **Interactive Chokepoint Remediation Simulation**: Allows security engineers to click any relationship in the visual graph, simulate revoking it, and immediately verify whether the attack path is eliminated or re-routes through alternate permissions.
4. **Blast Radius Quantification**: Calculates total downstream reachable assets if an identity is compromised, classifying critical infrastructure exposure.
5. **Decoupled Threat Narration**: Employs an LLM strictly as an executive briefing narrating findings *after* graph algorithms have proven the vulnerability mathematically.

---

## 3. High-Level System Architecture

```
+-----------------------------------------------------------------------------------+
|                              ZENITH ARCHITECTURE                                   |
+-----------------------------------------------------------------------------------+
                                        |
     [ LANDING PAGE ]                   |               [ INTERACTIVE CONSOLE ]
     Ambient Video Canvas               |               React 18 + Vite
     Animated SOC Telemetry             |               Force-Directed 2D Graph Canvas
     Brand Showcase & CTAs              |               Attack Path Inspector & Drawer
            |                           |               Blast Radius & Remediation UI
            +---------------------------+---------------------------+
                                        |
                                        v
                       +---------------------------------+
                       |       EXPRESS BACKEND API       |
                       |       (Node.js / Port 4000)     |
                       |   - /api/graph                  |
                       |   - /api/paths                  |
                       |   - /api/blast-radius/:id       |
                       |   - /api/simulate-remediation   |
                       |   - /api/explain-path           |
                       |   - /api/inject                 |
                       +---------------------------------+
                                 |              |
           Cypher Queries via    |              | Narration Request
           Bolt Driver Protocol  |              | (Decoupled LLM Layer)
                                 v              v
               +--------------------+   +-----------------------+
               |  NEO4J GRAPH DB    |   | THREAT NARRATION      |
               |  (Port 7687 Bolt)  |   | SERVICE               |
               |  - Directed Nodes  |   | (LLM / MITRE Engine)  |
               |  - Weighted Edges  |   +-----------------------+
               |  - Graph Traversal |
               +--------------------+
```

---

## 4. Graph Data Model & Attack Taxonomy

### 4.1 Node Entities ($V$)
The identity graph models four primary entity classes:
| Node Label | Identifier Prefix | Description | Criticality Flag |
| :--- | :--- | :--- | :--- |
| **`User`** | `user-X` | Human enterprise accounts (contractors, analysts, engineers). | `critical: false` |
| **`Group`** | `grp-X` | Security groups (e.g., HelpDesk, IT-Admins, `Domain Admins`). | `critical: true` for Tier-0 groups |
| **`Machine`** | `machine-X` | Domain Controllers, servers, workstations (`HOST-X`). | `critical: true` for Domain Controllers |
| **`ServiceAccount`** | `svc-X` | Non-human identities running background tasks, backups, APIs. | Dependent on privilege level |

### 4.2 Relationship Taxonomy ($E$) & Exploit Weights
Each edge represents a privilege, delegation, or exploit vector. The `weight` represents **exploit difficulty and operational friction** (1 = trivial/silent; 10 = loud, high-friction, complex).

$$\text{Path Cost } C(P) = \sum_{e \in P} \text{weight}(e)$$

| Relationship Type | Label | Weight | MITRE ATT&CK Mapping | Security Meaning & Exploit Mechanics |
| :--- | :--- | :---: | :--- | :--- |
| **`MEMBER_OF`** | `MemberOf` | **1** | T1078 (Valid Accounts) | Principal is a direct member of security group. Silent and automatic. |
| **`ADMIN_TO`** | `AdminTo` | **2** | T1078.002 (Domain Accounts) | Principal possesses local administrator rights on target host/group. |
| **`CAN_RDP`** | `CanRDP` | **3** | T1021.001 (Remote Desktop Protocol) | Principal has network and policy rights to initiate interactive RDP session. |
| **`HAS_SESSION`** | `HasSession` | **2** | T1003.001 (LSASS Memory) | Target host holds an active or cached credential token in LSASS for principal. |
| **`CAN_RESET_PASSWORD_OF`**| `CanResetPasswordOf` | **4** | T1098 (Account Manipulation) | Principal has DACL permissions to force a password reset without old password. |
| **`OWNS`** | `Owns` | **3** | T1222 (File & Directory Permissions) | Object ownership grants ability to modify permissions (DACLs) at will. |
| **`TRUSTED_BY`** | `TrustedBy` | **5** | T1484 (Group Policy / Domain Trust) | Kerberos domain or host trust delegation allowing impersonation. |
| **`EXECUTE_DCOM`** | `ExecuteDCOM` | **4** | T1021.003 (Distributed COM) | Ability to trigger remote code execution via Distributed Component Object Model. |
| **`KERBEROASTABLE`** *(Phase 2)* | `Kerberoastable` | **2** | T1558.003 (Kerberoasting) | Service account with Service Principal Name (SPN) crackable offline. |
| **`GENERIC_ALL`** *(Phase 2)* | `GenericAll` | **1** | T1222.001 (AD Permissions Modification)| Full access control rights over target object (take ownership, reset password). |
| **`GPO_APPLIED_TO`** *(Phase 2)* | `GPOAppliedTo` | **3** | T1484.001 (Group Policy Modification) | Group Policy Object linked to container; compromising GPO compromises all child hosts. |

---

## 5. Mathematical Graph Algorithms & Scoring Model

### 5.1 Cheapest Attack Path Discovery (Dijkstra-Equivalent via Cypher)
Rather than simple unweighted BFS hop counting, ZENITH computes the cumulative cost of edge traversal:

```cypher
MATCH (start {id: $fromId}), (end {id: $toId})
MATCH p = (start)-[*1..6]->(end)
WITH p, reduce(cost = 0, r IN relationships(p) | cost + r.weight) AS totalCost
RETURN p, totalCost
ORDER BY totalCost ASC
LIMIT $limit
```

### 5.2 Explainable Risk Scoring Engine
ZENITH rejects black-box neural scoring in favor of a **transparent, 100% explainable security metric**:

$$\text{Risk Score} = \max\left(5, \min\left(100, 100 - (\text{TotalCost} \times 3.5) - (\text{Hops} \times 2) + \Delta_{\text{crit}} + \Delta_{\text{choke}}\right)\right)$$

- **Total Cost Impact**: Lower exploit friction directly increases the risk score (easier for adversaries).
- **Hops Impact**: Shorter paths require fewer attacker actions and generate less telemetry.
- **Target Criticality Bonus ($\Delta_{\text{crit}}$)**: Adds $+15$ points if the destination target is flagged `critical: true` (e.g., Domain Controllers, Domain Admins).
- **Explainability**: "Risk reflects path exploitability weighted inversely by friction, hop count, and asset tier."

### 5.3 Downstream Blast Radius Quantification
Computes full reachability from a compromised node up to $N$ hops:

```cypher
MATCH (start {id: $nodeId})
MATCH (start)-[*1..6]->(reachable)
RETURN DISTINCT reachable.id AS id, reachable.name AS name,
       labels(reachable)[0] AS type, reachable.critical AS critical
```

### 5.4 Chokepoint Remediation Simulation
Computes whether removing a specific permission $r_{\text{target}}$ eliminates all paths between source and destination:

```cypher
MATCH (start {id: $fromId}), (end {id: $toId})
MATCH p = (start)-[*1..6]->(end)
WHERE NOT $excludeRelId IN [r IN relationships(p) | elementId(r)]
  AND NOT $excludeRelId IN [r IN relationships(p) | toString(id(r))]
RETURN count(p) AS remainingPaths
```

---

## 6. Guaranteed Planted Attack Scenarios (Live Demo Paths)

ZENITH’s synthetic seed generator includes mathematically guaranteed, multi-hop planted attack paths designed for live judge evaluation:

### Planted Path 1: Credential Cache Hijack (3 Hops)
```
[ user-3 ]
   |
   |  CanRDP (Cost: 3)
   v
[ HOST-5 (machine-5) ]
   |
   |  HasSession (Cost: 2)  <-- CRITICAL CHOKEPOINT
   v
[ svc-account-0 (svc-0) ]
   |
   |  CanResetPasswordOf (Cost: 4)
   v
[ Domain Admins (grp-domain-admins) ]
```
- **Cumulative Cost**: $3 + 2 + 4 = 9$
- **Risk Score**: 58 / 100
- **Remediation Moment**: Revoking `HOST-5 --[HasSession]--> svc-account-0` completely eliminates this path (`remainingPaths: 0`).

### Planted Path 2: Cross-Host Trust & Lateral Movement (4 Hops)
```
[ user-17 ]
   |
   |  ExecuteDCOM (Cost: 4)
   v
[ HOST-8 (machine-8) ]
   |
   |  TrustedBy (Cost: 5)
   v
[ HOST-2 (machine-2) ]
   |
   |  HasSession (Cost: 2)
   v
[ svc-account-1 (svc-1) ]
   |
   |  AdminTo (Cost: 2)
   v
[ Domain Admins (grp-domain-admins) ]
```
- **Cumulative Cost**: $4 + 5 + 2 + 2 = 13$
- **Risk Score**: 40 / 100

---

## 7. Backend API Specification

| Method | Endpoint | Query / Body Parameters | Response Payload | Description |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/graph` | None | `{ nodes: [...], links: [...] }` | Full node/edge graph payload for force-directed canvas. |
| `GET` | `/api/paths` | `from=user-3&to=grp-domain-admins` | `{ from, to, paths: [{ hops, totalCost, riskScore, steps }] }` | Ranked attack paths between any two graph identities. |
| `GET` | `/api/blast-radius/:id` | Route param `:id` | `{ nodeId, reachableCount, reachable: [...] }` | All downstream reachable nodes from selected identity. |
| `POST` | `/api/simulate-remediation`| `{ from, to, excludeRelId }` | `{ pathEliminated: bool, remainingPathCount: int, alternatePath?: [...] }` | Tests whether revoking a relationship breaks the attack path. |
| `POST` | `/api/explain-path` | `{ steps, totalCost, riskScore, targetName }` | `{ executiveSummary, techniqueBreakdown, recommendations }` | Decoupled LLM narration of the mathematically computed path. |
| `POST` | `/api/inject` | `{ from, to, relationshipType }` | `{ success: bool, edge: {...} }` | Live edge injection proving real-time graph computation. |

---

## 8. Technology Stack Summary

| Component | Technology | Rationale / Specification |
| :--- | :--- | :--- |
| **Database** | Neo4j 2026.08 + Cypher / GQL | Enterprise ACID graph database; native pointer-hopping path traversal. |
| **Backend Runtime** | Node.js 26.8.2 + Express 4.19 | High-throughput asynchronous Bolt driver orchestration. |
| **Graph Visualization** | `react-force-graph-2d` + HTML5 Canvas | Smooth 60 FPS physics simulation capable of handling hundreds of interconnected nodes. |
| **Frontend Framework** | React 18 + Vite 5.4 | Ultra-fast HMR and modular component architecture. |
| **Styling & Aesthetics** | Custom Vanilla CSS + Glassmorphism | Dark theme inspired by modern Security Operations Centers (SOC). |
| **Landing Page** | HTML5 + CSS3 + Video Stream | High-production brand gateway with dynamic stat counters. |

---

## 9. Phase Delivery Roadmap

- [x] **Phase 1: Environment & Core Pipeline Verification** (Node.js, Neo4j, seed script, query verification, Cypher integer/elementId bug fixes).
- [ ] **Phase 2: Scaled Enterprise Dataset** (Expand to ~120-140 nodes, add `KERBEROASTABLE`, `GENERIC_ALL`, `GPO_APPLIED_TO`).
- [ ] **Phase 3: Explainable Risk Scoring & Blast-Radius UI** (Incorporate target criticality, build Blast Radius Drawer).
- [ ] **Phase 4: Full Interactive Remediation** (Click any canvas edge, compute rerouted alternate paths, before/after UI).
- [ ] **Phase 5: Decoupled LLM Threat Narration Layer** (`/api/explain-path` endpoint with MITRE ATT&CK intelligence).
- [ ] **Phase 6: Live Judge Scenario Injection** (`/api/inject` UI panel to demonstrate real-time Cypher recalculation).
- [ ] **Phase 7: Landing Page & Console Integration + DEMO_SCRIPT.md** (Unified navigation, projector-ready typography, 3-minute pitch script).
