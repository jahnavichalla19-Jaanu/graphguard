# GraphGuard

GraphGuard bridges CI/CD pipelines (GitHub Actions) and cloud IAM into a unified knowledge graph in FalkorDB.
It discovers multi-hop supply chain attack paths traversing from untrusted code triggers to sensitive cloud resources.
Traditional scanners inspect single-hop configuration files; GraphGuard explores deep transitive blast radii.
It calculates load-bearing choke points to deliver actionable remediation plans that eliminate entire attack classes.
An autonomous AI reasoning copilot provides zero-hallucination analysis backed by deterministic graph validation.

---

## Run in One Command

Run GraphGuard and FalkorDB together with Docker Compose:

```bash
docker compose up
```

Once running, navigate to:
**[http://localhost:8080](http://localhost:8080)**

**No API key is required and nothing needs to be configured.** GraphGuard boots with full local functionality out of the box.

---

## No API Key Needed

GraphGuard uses a deterministic offline router as its default AI agent engine. The offline router executes graph traversals, validates node identities, performs blast radius calculations, and suggests architectural choke points entirely locally without external network dependencies.

An Anthropic Claude API key is **optional** via the environment:
```bash
export ANTHROPIC_API_KEY="your-optional-key"
```
GraphGuard never stores API keys or secrets in files, repositories, or databases. Zero environment variables are required to run the full application.

---

## Architecture & Tech Stack

- **Framework**: Spring Boot 4.1.1 (Java 25)
- **Graph Database**: [FalkorDB](https://www.falkordb.com/) (High-performance Cypher-based graph database)
- **AI / Reasoning**: Deterministic offline graph router with optional Anthropic Claude tool-calling agent
- **Data Ingestion**: Jackson YAML/JSON parsers for GitHub Actions workflows and AWS IAM authorization policies
- **Frontend**: Interactive Cytoscape.js graph visualizer, real-time stats bar, and security chat interface (`src/main/resources/static/`)

---

## What GraphGuard Finds (and What It Doesn't)

### What GraphGuard Finds
- **Cross-Domain Attack Paths**: Attack paths appear **only** when an untrusted trigger (`pull_request_target`, `issue_comment`, `workflow_run`) reaches a sensitive sink node (such as repository secrets or cloud resources).
- **Static CI/CD Rule Violations**: GraphGuard independently inspects workflows for misconfigurations, including unpinned 3rd-party actions (`GG-CI-004`) and excessive `write-all` permissions (`GG-CI-005`).
- **Architectural Choke Points**: Identifies specific relationships whose severance dismantles multiple attack paths simultaneously.

### What GraphGuard Doesn't (Zero False Positives by Design)
- **Normal Workflow Triggers**: Standard repositories triggered by `push` or `pull_request` (running on fork heads without secret exposure) correctly show **0 attack paths**. Static rule findings still fire, but no spurious paths to cloud resources are generated.
- **Unmatched IAM Roles**: When scanning a live GitHub repository, workflows are fetched directly from GitHub, but cloud IAM policies come from the loaded sample or an uploaded `aws iam get-account-authorization-details` JSON file (`POST /api/ingest/aws-iam` / `/api/ingest/aws-file`). If `role-to-assume` ARNs in workflow files do not match roles in the loaded IAM state, GraphGuard produces explicit "unmatched role" warnings and does not fabricate cloud paths.
- **Live AWS API Ingestion**: Live AWS API ingestion (`/api/ingest/aws-live`) is **not implemented**. Static file import via `POST /api/ingest/aws-iam` (or the preloaded sample IAM model) is the supported ingestion method.

---

## Demo & Verification

- **Automated Verification Script**: Run [`scripts/demo.sh`](scripts/demo.sh) for an end-to-end automated API verification sequence.
- **Vulnerable Test Repo**: Explore [`demo/vulnerable-repo`](demo/vulnerable-repo) — an intentionally vulnerable sample repository ready to push to your GitHub account to test live ingestion.
- **90-Second Judge Runbook**: Follow [`docs/DEMO.md`](docs/DEMO.md) for the fast judge demo walkthrough.

### Quick API Verification Steps

```bash
# 1. Health check & active graph verification
curl -s http://localhost:8080/api/health

# 2. Ingest sample multi-tier dataset (workflows + IAM)
curl -s -X POST http://localhost:8080/api/ingest/sample

# 3. Discover multi-hop attack paths
curl -s http://localhost:8080/api/paths

# 4. Identify high-leverage choke points
curl -s http://localhost:8080/api/choke-points

# 5. Measure blast radius at depth 1 vs depth 4
curl -s "http://localhost:8080/api/blast-radius?node=cool-org/cool-linter@v2&depth=1"
curl -s "http://localhost:8080/api/blast-radius?node=cool-org/cool-linter@v2&depth=4"

# 6. PageRank centrality for load-bearing infrastructure
curl -s "http://localhost:8080/api/load-bearing?limit=5"

# 7. Simulate fix on ephemeral graph (does not mutate main graph)
curl -s -X POST http://localhost:8080/api/simulate-fix \
  -H "Content-Type: application/json" \
  -d '{"source":"cool-org/cool-linter@v2","type":"ASSUMES","target":"role:deployer"}'

# 8. Inspect rule findings
curl -s http://localhost:8080/api/findings

# 9. Ask Copilot about non-existent nodes (zero hallucination guard)
curl -s -X POST http://localhost:8080/api/agent/ask \
  -H "Content-Type: application/json" \
  -d '{"question":"blast radius of ghost-service"}'
```

---

## Design Rules & Cypher Mechanics

- **Strict Parameterized Cypher**: Every Cypher query executed against FalkorDB uses parameters (`$param`). Dynamic interpolation is restricted exclusively to validated positive integer depths or whitelisted relationship labels.
- **Read/Write Segregation**: Graph queries inspecting topology execute over read-only connections (`readOnlyQuery`), while mutations use write connections.
- **Four Explicit Outcomes**: All tool evaluations, agent answers, and API responses categorize execution into four deterministic outcomes:
  1. `answered_with_path`: A traversal or attack path was successfully computed.
  2. `memory`: Past security decisions or audit findings were stored or retrieved.
  3. `not_in_graph`: The query target exists, but no connecting paths or reachable nodes were found.
  4. `unknown_node`: The referenced identifier does not match any node in the graph.
- **Zero Hallucination Guard**: The agent's output is scanned for node identifiers. If any identifier is absent from the verified tool execution trace, the response is discarded and replaced with factual data derived directly from query result rows.
- **Plan-Only Remediation**: Remediation simulations run on temporary ephemeral graphs (`sim_*`) or return early if an edge does not exist, guaranteeing the main production graph is never mutated during what-if analysis.

---

## Performance & Engineering Optimizations

> [!NOTE]
> Live FalkorDB curl response timings were not benchmarked in this environment because the Docker Desktop daemon was inactive on the host machine.

GraphGuard implements several key architectural optimizations:
1. **Path Result Caching**: Main graph attack path calculations are cached in memory and automatically invalidated upon write operations (`loadMain`, `loadIam`, `acceptRisk`).
2. **Traversal Edge-Type Whitelisting**: Graph reachability and blast radius queries restrict edge traversals to explicit relationship types (`EDGE_TYPES`), pruning unneeded paths early.
3. **Startup Index Creation**: FalkorDB node indices on labels (`Trigger`, `Workflow`, `Job`, `Action`, `Secret`, `Role`, `Resource`) are created once during initialization.
4. **Concurrent Ingestion**: GitHub Actions workflow discovery uses a concurrent thread pool (4–5 threads) for parallel fetching.
5. **UI Deduplication & Loading States**: The frontend deduplicates concurrent in-flight GET requests and displays an active loading indicator during async operations.

---

## Automated Test Suite

GraphGuard includes a comprehensive test suite of **36 automated unit and integration tests** passing with **0 failures**:

- `GraphGuardTest.java`: 12 tests covering end-to-end sample ingestion, single/multi-hop blast radius, unknown node detection, PageRank centrality, shortest paths, ephemeral fix simulation, memory persistence, risk acceptance, and agent hallucination defenses.
- `DetectionEngineTest.java`: Comprehensive rule detection coverage validating rules GG-CI-001 through GG-CI-005, edge cases, and path synthesis.
- `AwsIamTest.java`: Tests covering IAM policy parsing, statement expansion, action matching, role assumption graph construction, and resource attachment.

Run the test suite locally:
```powershell
# Windows
.\mvnw.cmd test

# Linux / macOS
./mvnw test
```

---

## Known Limits

- **No Authentication / Authorization**: Designed as an internal security engineering tool and local assessment engine; API endpoints do not require authentication.
- **Java 25 Required**: If running without Docker, Java 25 (or higher) is required by the Spring Boot 4 toolchain.
- **Static IAM Model**: File and JSON import is supported (`POST /api/ingest/aws-iam`), but live AWS API ingestion (`/api/ingest/aws-live`) is not implemented.
- **Complex GitHub Actions Syntax**: Dynamic matrix jobs and private reusable workflows requiring specialized token permissions are not parsed.

---

## License

GraphGuard is released under the [MIT License](LICENSE). Copyright (c) 2026 GraphGuard contributors.
