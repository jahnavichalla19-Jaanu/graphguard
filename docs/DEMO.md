# GraphGuard: 90-Second Judging Demo Script & Runbook

This runbook guides presenters and judges through a rapid, 90-second demonstration of GraphGuard's multi-hop CI/CD and cloud supply chain attack graph analysis.

For hands-free automated verification, you can run [`scripts/demo.sh`](../scripts/demo.sh). To test live GitHub scanning against an intentionally vulnerable repo, see [`demo/vulnerable-repo`](../demo/vulnerable-repo).

---

## 90-Second Judging Runbook

### 0:00 – 0:15: Health & Dual-Surface Ingestion
1. Ensure FalkorDB and GraphGuard are running:
   ```bash
   curl -s http://localhost:8080/api/health
   ```
   *Expected response:* `{"status":"ok","graph":"graphguard"}`
2. Open the web UI at `http://localhost:8080/` and click **"Load Demo Graph"** (or trigger via API):
   ```bash
   curl -s -X POST http://localhost:8080/api/ingest/sample
   ```
3. **Presenter pitch:**
   > *"GraphGuard bridges developer CI/CD workflows and cloud infrastructure into a unified FalkorDB knowledge graph. Ingesting workflows and AWS IAM policies creates the connected graph needed to trace multi-hop attack vectors."*

---

### 0:15 – 0:35: Attack Path Discovery & Choke Points
1. Click **"Find Attack Paths"** in the UI, or execute:
   ```bash
   curl -s http://localhost:8080/api/paths
   ```
   *Observation:* Uncovers 3 distinct multi-hop attack paths (3, 5, and 6 hops) originating from untrusted fork PR triggers reaching sensitive assets (repository secrets and `customer-db`).
2. Click **"Fix-First Ranking"** or query choke points:
   ```bash
   curl -s http://localhost:8080/api/choke-points
   ```
   *Observation:* Highlights top choke points. The top edge (`cool-org/cool-linter@v2 -> role:deployer`) cuts across multiple paths simultaneously.

---

### 0:35 – 0:50: Architectural Blast Radius & Fix Simulation
1. Click **"Depth Contrast"** with node `cool-org/cool-linter@v2` (or call `/api/blast-radius`):
   ```bash
   # Single-hop view (traditional scanner perspective)
   curl -s "http://localhost:8080/api/blast-radius?node=cool-org/cool-linter@v2&depth=1"

   # Multi-hop graph traversal (GraphGuard perspective)
   curl -s "http://localhost:8080/api/blast-radius?node=cool-org/cool-linter@v2&depth=4"
   ```
   *Observation:* Depth 1 shows only 1 immediate neighbor (the CI step). Depth 4 reveals 7 reachable downstream nodes culminating in production `customer-db`.
2. Click **"Simulate Fix"** on the choke point edge, or POST to `/api/simulate-fix`:
   ```bash
   curl -s -X POST http://localhost:8080/api/simulate-fix \
     -H "Content-Type: application/json" \
     -d '{"source":"cool-org/cool-linter@v2","type":"ASSUMES","target":"role:deployer"}'
   ```
   *Observation:* Evaluates the impact on an ephemeral graph without touching production data, verifying that breaking this edge eliminates the active attack paths.

---

### 0:50 – 1:05: Load-Bearing Infrastructure & Rule Findings
1. Click **"Most Depended-On"** to compute PageRank centrality via `algo.pageRank`:
   ```bash
   curl -s "http://localhost:8080/api/load-bearing?limit=5"
   ```
   *Observation:* Ranks bridge entities like `role:deployer` and `role:admin` as high-centrality dependencies.
2. Review rule findings across the posture:
   ```bash
   curl -s http://localhost:8080/api/findings
   ```
   *Observation:* Enumerates rule violations (e.g. unpinned action references GG-CI-004, overly permissive workflows GG-CI-005).

---

### 1:05 – 1:20: Zero-Hallucination AI Copilot (4 Outcomes)
1. In the UI copilot chat box, ask a question about an unknown entity:
   > *"What is the blast radius of ghost-service?"*
2. Or query `/api/agent/ask`:
   ```bash
   curl -s -X POST http://localhost:8080/api/agent/ask \
     -H "Content-Type: application/json" \
     -d '{"question":"What is the blast radius of ghost-service?"}'
   ```
3. **Presenter pitch:**
   > *"Every agent query is deterministically validated against the graph topology. Because `ghost-service` is not in the graph, the agent returns `unknown_node` with 0 rows and zero hallucinated paths."*

---

### 1:20 – 1:30: Audit Memory & Resilient Relinking
1. Post an audit finding or risk acceptance:
   ```bash
   curl -s -X POST http://localhost:8080/api/findings \
     -H "Content-Type: application/json" \
     -d '{"node":"role:deployer","text":"Temporary risk acceptance for staging migration"}'
   ```
2. Reload sample data (`POST /api/ingest/sample`):
   *Observation:* Audit and decision nodes persist across graph resets, and `relinkMemory()` automatically restores semantic connections to the fresh topology.

---

## Complete API Reference Checklist

| Endpoint | HTTP Method | Description |
| :--- | :--- | :--- |
| `/api/health` | `GET` | Health check and active graph confirmation |
| `/api/ingest/sample` | `POST` | Loads sample workflows and AWS IAM policies |
| `/api/paths` | `GET` | Computes active multi-hop attack paths |
| `/api/choke-points` | `GET` | Identifies single edges mitigating maximum attack paths |
| `/api/load-bearing` | `GET` | Runs PageRank centrality on graph nodes |
| `/api/blast-radius` | `GET` | Traverses downstream reachability for a target node |
| `/api/agent/ask` | `POST` | Natural language queries with zero-hallucination guard |
| `/api/simulate-fix` | `POST` | Ephemeral graph simulation of edge removal |
| `/api/findings` | `GET` / `POST` | Lists static rule violations or persists audit findings |
| `/api/ingest/github` | `POST` | Scans a live public GitHub repository |
| `/api/ingest/aws-iam` | `POST` | Ingests AWS IAM account authorization JSON or file |
| `/api/decisions` | `POST` | Records risk acceptance decisions on paths |
