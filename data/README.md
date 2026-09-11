# ZENITH Identity Privilege Graph Dataset

This directory contains the specification, taxonomy schema, and seed definitions for the synthetic Active Directory identity privilege graph utilized by **ZENITH**.

---

## 1. Graph Topology Overview

The dataset models an enterprise Active Directory domain environment comprising **127 nodes** and over **300 privilege edges** stored as a directed property graph in **Neo4j**:

| Identity Type | Label | Count | Description |
| :--- | :--- | :--- | :--- |
| **Tier-0 Apex** | `Group` | 1 | `grp-domain-admins` (Domain Admins, root administrative objective) |
| **Groups** | `Group` | 12 | Enterprise organizational units (IT-Ops, HelpDesk, Workstation-Admins, etc.) |
| **Users** | `User` | 75 | Standard domain accounts (`user-0` through `user-74`) |
| **Service Accounts**| `ServiceAccount` | 15 | Privileged service identities (`svc-0` through `svc-14`) |
| **Computers** | `Computer` | 24 | Workstations, domain controllers, database servers (`machine-0` to `machine-23`) |

---

## 2. Privilege Relationship Taxonomy & Exploit Weights

Relationships represent lateral traversal or privilege escalation vectors with an associated Dijkstra exploit resistance weight ($w \in [1, 10]$):

| Relationship | Weight | MITRE Technique | Description |
| :--- | :---: | :--- | :--- |
| `MemberOf` | 1 | T1078 Valid Accounts | Group membership (passive inheritance) |
| `HasSession` | 2 | T1003.001 LSASS Memory | Active interactive logon session vulnerable to memory harvesting |
| `CanRDP` | 3 | T1021.001 Remote Desktop | Interactive GUI lateral traversal over TCP 3389 |
| `AdminTo` | 4 | T1078.002 Local Admin | Local administrative access on target host |
| `ExecuteDCOM` | 5 | T1021.003 DCOM | Remote command execution via MMC20.Application / ShellWindows |
| `CanResetPasswordOf`| 4 | T1098 Account Manipulation | AD DACL `ForceChangePassword` right enabling account takeover |
| `GenericAll` | 6 | T1098.001 ACL Abuse | Full control permissions allowing DACL and membership rewrites |
| `Kerberoastable` | 5 | T1558.003 Kerberoasting | SPN registered on service account susceptible to offline TGS cracking |
| `GPOAppliedTo` | 7 | T1484.001 Group Policy | Group Policy Object link applying configuration tasks |

---

## 3. Deliberately Planted Attack Paths

The seed dataset contains 4 deterministic attack paths to ensure consistent, non-obvious evaluation for security audits:

1. **Path 1: RDP Session Hijacking (3 Hops, Cost: 9, Risk: 58/100)**:
   $$\text{user-3} \xrightarrow{\text{CanRDP}} \text{machine-5} \xrightarrow{\text{HasSession}} \text{svc-0} \xrightarrow{\text{CanResetPasswordOf}} \text{grp-domain-admins}$$
   *Chokepoint*: Revoking `machine-5 -[HasSession]-> svc-0` isolates the Domain Admin group.

2. **Path 2: DCOM Host Trust Pivot (4 Hops, Cost: 16, Risk: 42/100)**:
   $$\text{user-12} \xrightarrow{\text{AdminTo}} \text{machine-8} \xrightarrow{\text{ExecuteDCOM}} \text{machine-19} \xrightarrow{\text{HasSession}} \text{svc-4} \xrightarrow{\text{GenericAll}} \text{grp-domain-admins}$$

3. **Path 3: Group Policy & ACL Abuse (3 Hops, Cost: 14, Risk: 51/100)**:
   $$\text{user-25} \xrightarrow{\text{MemberOf}} \text{grp-4} \xrightarrow{\text{GPOAppliedTo}} \text{machine-2} \xrightarrow{\text{AdminTo}} \text{grp-domain-admins}$$

4. **Path 4: Kerberoasting Service Pivot (3 Hops, Cost: 12, Risk: 54/100)**:
   $$\text{user-7} \xrightarrow{\text{CanRDP}} \text{machine-11} \xrightarrow{\text{Kerberoastable}} \text{svc-7} \xrightarrow{\text{GenericAll}} \text{grp-domain-admins}$$

---

## 4. Re-generating the Dataset

To re-seed the live Neo4j instance at any time:
```bash
npm run seed
# or
node src/backend/scripts/seedData.js
```
