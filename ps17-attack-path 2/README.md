# PS17 - Attack path & identity privilege graph analyzer

Starter template for Kurukshetra 2.0, Domain 2, PS17. Models an
identity/asset graph (users, groups, service accounts, machines) in
Neo4j, finds privilege-escalation attack paths between any two nodes,
computes blast radius, and lets you simulate remediation (revoke one
edge, re-check if the path disappears).

## Architecture

```
Synthetic org generator (scripts/seedData.js)
        |
        v
Neo4j graph database  (stores nodes + weighted relationships,
                        runs path-finding via Cypher)
        |
        v
Express API (backend/)  --  /api/graph, /api/paths,
                             /api/blast-radius/:id,
                             /api/simulate-remediation
        |
        v
React frontend (frontend/)  --  force-directed graph view,
                                 red-highlighted attack path,
                                 remediation simulator
```

## 1. Get a Neo4j instance

Easiest for a hackathon: **Neo4j Aura Free** (https://neo4j.com/cloud/aura-free/)
- Create a free instance, note the connection URI, username, password.

Or run locally with Docker:
```
docker run -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password123 neo4j:5
```

If your instance supports the APOC plugin (Aura Free and the Docker
image both do by default in recent versions), the seed script uses it
for cleaner dynamic node/relationship creation. If APOC isn't
available, the seed script automatically falls back to plain Cypher
per node/relationship type - no changes needed.

## 2. Backend setup

```
cd backend
cp .env.example .env
# edit .env with your Neo4j URI / user / password
npm install
npm run seed      # generates and loads the synthetic org graph
npm start         # starts the API on http://localhost:4000
```

## 3. Frontend setup

```
cd frontend
npm install
npm run dev        # starts on http://localhost:5173
```

## 4. Try it

1. Open the frontend. You'll see the full graph.
2. In the sidebar, set "From" to `user-3` and "To" to `grp-domain-admins`,
   then click "Find attack paths". This surfaces a planted 3-hop path
   (RDP -> cached session -> password reset on Domain Admins).
3. Try `user-17` -> `grp-domain-admins` for a second, longer planted
   path (DCOM execution -> machine trust -> service account session -> admin).
4. Click "Simulate: revoke first edge" to see whether removing that one
   privilege breaks the path - this is your "remediation" demo moment.

## What to build next (suggested order)

1. Verify the seed script runs and the two planted paths are findable -
   this proves the core pipeline works end-to-end.
2. Add a few more relationship types / a larger synthetic org (100+
   nodes) so the graph looks convincingly enterprise-scale for the demo.
3. Wire up an LLM explanation layer: given a path's `steps` array from
   `/api/paths`, prompt an LLM to explain in plain English why the path
   is dangerous and what to remediate - this is the only place an LLM
   should touch the pipeline (see the earlier architecture discussion).
4. Polish the remediation flow: currently it revokes the *first* edge
   in the cheapest path by default - consider letting the user click
   any edge in the graph and revoke that one specifically.
5. Add a risk-scoring legend / dashboard view summarizing "top 5 most
   dangerous paths in the org" computed from all users to Domain Admins,
   not just a single from/to pair - stronger demo material.
6. Style pass on the frontend (currently intentionally bare-bones).

## Notes on the relationship taxonomy

Defined in `backend/config/relationshipTypes.js` - 8 relationship types,
each with an "exploit difficulty" weight used for cheapest-path ranking.
Add more types here as you research real-world identity attack
techniques (e.g. Kerberoasting, ACL abuse, GPO abuse) if you want to
go deeper technically before the hackathon.
