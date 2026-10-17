# GraphGuard 90-Second Judging Demo Script

## Fast Demo Runbook (0:00 - 1:30)

### 0:00 - 0:15: Ingestion & Dual-Surface Knowledge Graph
1. Open the UI at `http://localhost:8080/`.
2. Click **"Load Demo Graph"** (`POST /api/ingest/sample`).
3. Explain to judges:
   > *"GraphGuard solves the blind spot between developer CI/CD workflows and cloud infrastructure by stitching GitHub Actions pipelines directly with AWS IAM roles and sensitive databases into FalkorDB."*

### 0:15 - 0:35: Attack Path Discovery & Fix-First Ranking
1. Click **"Find Attack Paths"** (`GET /api/paths`).
   - Notice the 3 distinct multi-hop attack paths (3, 5, and 6 hops) leading from untrusted fork PR events to the production `customer-db`.
2. Click **"Fix-First Ranking"** (`GET /api/choke-points`).
   - Show how GraphGuard identifies the single choke-point relationship whose remediation breaks multiple attack vectors simultaneously.

### 0:35 - 0:50: Blast Radius & Depth Contrast
1. Click **"Depth Contrast"** and enter `cool-org/cool-linter@v2`.
2. Observe the dramatic contrast:
   - **Depth 1**: 1 immediate neighbor (the CI step).
   - **Depth 4**: 7 reachable nodes deep inside the infrastructure, reaching `customer-db`.
   > *"Traditional scanners see depth 1; graph traversal reveals the complete 4-hop blast radius."*

### 0:50 - 1:05: Most Depended-On (PageRank)
1. Click **"Most Depended-On"** (`GET /api/load-bearing?limit=5`).
   - Demonstrate `CALL algo.pageRank` identifying high-centrality bridge roles like `role:deployer` and `role:admin`.

### 1:05 - 1:20: Zero-Hallucination AI Copilot (4 Outcomes)
1. In the AI chat prompt, type:
   `blast radius of payment-service`
2. Show judges:
   - Outcome badge: `[UNKNOWN NODE]`.
   - Result: 0 rows, exact server error, zero hallucinated identifiers or guessed routes.
   > *"Every tool call validates node identity. If an identifier is not in the graph, the answer sanitizer enforces strict factual accuracy."*

### 1:20 - 1:30: Graph Memory & Resilient Relinking
1. Accept a risk on Path 1 or post an audit finding via `POST /api/findings`.
2. Reload sample data:
   - Decision and Finding memory nodes are preserved across graph resets.
   - `relinkMemory()` automatically restores `APPLIES_TO` and `ABOUT` edges to the new graph topology.
