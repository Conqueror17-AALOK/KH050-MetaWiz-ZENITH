# ZENITH — Live Demo Script (3-Minute Pitch)
## Kurukshetra 2.0 | Domain 2: Cybersecurity & Blockchain

This script outlines the exact click-by-click sequence and verbal talking points for presenting **ZENITH** live to judges.

---

### Timing Breakdown
- **0:00 – 0:30**: Problem Statement & Architectural Hook
- **0:30 – 1:15**: Deterministic Attack Path Traversal & Risk Scoring
- **1:15 – 1:45**: Downstream Blast Radius Quantification
- **1:45 – 2:20**: Interactive Remediation Simulation (The "Hero Moment")
- **2:20 – 2:45**: Decoupled LLM Threat Narration (MITRE ATT&CK)
- **2:45 – 3:00**: Live Judge Scenario Injection (Proving Real-Time Graph Reasoning)

---

### Act 1: The Problem & Architectural Hook (0:00 – 0:30)

**What to do on screen**:
- Start on the **ZENITH Landing Page** (`landing-page/index.html`) showcasing ambient telemetry.
- Click **"Launch Console"** to transition into the interactive graph canvas (`http://localhost:5173`).

**What to say**:
> *"Judges, in enterprise environments like Active Directory and Cloud IAM, individual permissions look harmless in isolation. A helpdesk user can RDP to a workstation; that workstation has a cached session from a backup account; that backup account can reset a group password. Standard compliance tools pass them. Chained together, they create a catastrophic, multi-hop attack path to Domain Admin.*
>
> *Inspired by SpecterOps BloodHound, we built **ZENITH**—a deterministic privilege graph analyzer. Our core architectural rule: **real graph math finds attack paths, never LLM guesswork**. The LLM only narrates after Cypher has proven the vulnerability mathematically."*

---

### Act 2: Deterministic Attack Path Discovery (0:30 – 1:15)

**What to do on screen**:
1. Click the top bar preset: **`Demo 1: RDP Session (user-3)`**.
2. Click **"Find Attack Paths"**.
3. Point out the glowing neon-red path traversing across the canvas.
4. Show the sidebar card:
   - **3 Hops**
   - **Cost: 9**
   - **Risk Score: 58/100 (HIGH THREAT)**
   - Step 1: `user3 --[CanRDP]--> HOST-5`
   - Step 2: `HOST-5 --[HasSession]--> svc-account-0`
   - Step 3: `svc-account-0 --[CanResetPasswordOf]--> Domain Admins`
5. Click preset **`Demo 3: GPO Abuse (user-42)`** to show modern AD/cloud techniques:
   - `user42 --[GenericAll]--> GPO-Workstation-Lockdown --[GPOAppliedTo]--> WKSTN-12 --[HasSession]--> svc-gitlab-runner --[AdminTo]--> Domain Admins`.

**What to say**:
> *"Here, ZENITH executes a Dijkstra-weighted Cypher query over our 130-node enterprise graph in under 40 milliseconds. It discovers that `user-3` can RDP to `HOST-5`, harvest the LSASS credentials of `svc-account-0`, and reset the Domain Admin password.*
>
> *Our risk scoring is 100% explainable to judges: it starts from an 85-point baseline (+15 for Tier-0 critical targets) and deducts points for exploit friction and hop distance. Zero black-box neural guessing."*

---

### Act 3: Downstream Blast Radius Quantification (1:15 – 1:45)

**What to do on screen**:
1. In the sidebar, click the **"Blast Radius"** tab (or select `user-3` and click the Blast Radius button).
2. The graph lights up in **glowing amber/orange**.
3. Point out the telemetry metrics:
   - Total Downstream Reachable Entities (e.g. 6)
   - Critical Tier-0 Assets Compromised (Domain Admins flagged with red badge).

**What to say**:
> *"If an attacker compromises `user-3`, what is the true damage? Clicking 'Blast Radius' computes full transitive reachability. It instantly reveals that compromising this single contractor account cascades into 6 downstream assets, including Tier-0 Domain Admins. Security teams immediately know the blast radius before taking containment actions."*

---

### Act 4: Interactive Remediation Simulation (The "Hero Moment") (1:45 – 2:20)

**What to do on screen**:
1. Switch back to the **"Attack Paths"** tab.
2. In the Path #1 step list, point to Step 2: `HOST-5 --[HasSession]--> svc-account-0`.
3. Click the red **"Revoke"** button next to this edge (or click the link directly on the canvas).
4. Watch the UI immediately update:
   - The red attack path **visibly disappears**!
   - A bright green banner appears: **`CHOKEPOINT NEUTRALIZED: Revoking this privilege broke the attack chain. No alternate route exists to target.`**
5. (Optional) To demonstrate rerouting: click Demo 3 (`user-42`), revoke edge 2 (`GPOAppliedTo WKSTN-12`), and show the **`ATTACK PATH REROUTED`** banner with the alternate route rendered in golden amber!

**What to say**:
> *"This is ZENITH's critical remediation capability. Instead of guessing which permission to revoke, a security architect can test any edge in the graph. By revoking the cached LSASS session on `HOST-5`, ZENITH re-evaluates graph connectivity live via Cypher and proves that this single edge was the chokepoint—eliminating the attack path completely without disrupting other business operations."*

---

### Act 5: Decoupled LLM Threat Briefing (2:20 – 2:45)

**What to do on screen**:
1. Click the **"LLM Briefing"** tab (or click **"Generate LLM Briefing"**).
2. Show the structured security briefing:
   - Executive Threat Summary
   - Step-by-step MITRE ATT&CK technique breakdown:
     - `T1021.001` (RDP)
     - `T1003.001` (LSASS Credential Dumping)
     - `T1098` (Account Manipulation)
   - Chokepoint Recommendation & Remediation Playbook (Credential Guard, PAW architecture).

**What to say**:
> *"For compliance and C-suite reporting, our decoupled LLM service translates the mathematical graph steps into an executive threat briefing mapped directly to MITRE ATT&CK framework IDs and actionable hardening playbooks. The graph engine makes the mathematical decision; the LLM handles human narration."*

---

### Act 6: Live Judge Scenario Injection (2:45 – 3:00)

**What to do on screen**:
1. In the top bar, click **"+ Live Inject Edge"**.
2. Ask the judge for any user (e.g. `user-55`) and target (e.g. `machine-5`), or enter:
   - Source: `user-55`
   - Target: `machine-5`
   - Relationship: `CanRDP`
3. Click **"Inject Relationship Live"**.
4. Show the success notification, graph reload, and immediate recalculation of attack paths!

**What to say**:
> *"To prove this system reasons live and isn't a scripted video, judges can inject any identity or privilege right now. As soon as I inject a new RDP permission from `user-55` to `machine-5`, ZENITH immediately inserts the edge into Neo4j and recalculates the graph in real time, exposing the newly created attack path.*
>
> *ZENITH gives enterprises mathematical certainty over their identity attack surface. Thank you, and we welcome your questions!"*
