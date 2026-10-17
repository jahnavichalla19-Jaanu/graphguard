# GraphGuard

GraphGuard is an intelligent security analysis agent that builds and interrogates a graph joining CI/CD pipelines (GitHub Actions) with cloud IAM and sensitive resources.

## Architecture & Tech Stack

- **Framework**: Spring Boot 4.1.1 (Java 25)
- **Graph Database**: [FalkorDB](https://www.falkordb.com/) (High-performance Cypher-based Graph Database)
- **AI / LLM**: Anthropic Claude API tool-calling agent with offline fallback router
- **Data Ingestion**: Jackson YAML/JSON parsers for GitHub Actions workflows and IAM policies
- **Frontend**: Interactive graph visualization and chat interface in static web assets (`/`)

## Prerequisites

- Java 25 or higher
- Docker & Docker Compose (for running FalkorDB)
- Maven wrapper (`mvnw` / `mvnw.cmd` included)

## Getting Started

### 1. Start FalkorDB

Launch FalkorDB using Docker Compose:

```bash
docker compose up -d
```

- FalkorDB listens on port `6379`.
- The FalkorDB visual browser is accessible at `http://localhost:3000`.

### 2. Configure Environment Variables

Optional environment variables (can also be configured in `src/main/resources/application.yaml`):

- `FALKORDB_HOST`: FalkorDB host (default: `localhost`)
- `FALKORDB_PORT`: FalkorDB port (default: `6379`)
- `ANTHROPIC_API_KEY`: Anthropic Claude API key for natural language reasoning & tool use
- `ANTHROPIC_MODEL`: Anthropic model (default: `claude-sonnet-5-5`)
- `GITHUB_TOKEN`: GitHub personal access token for reading public/private repository workflows

### 3. Build & Run

Run the application using the Maven wrapper:

```powershell
# Windows
.\mvnw.cmd spring-boot:run

# Linux / macOS
./mvnw spring-boot:run
```

Once running:
- Open `http://localhost:8080/` in your browser to view the GraphGuard web UI.
- Health check: `GET http://localhost:8080/api/health`
- Ingest sample data: `POST http://localhost:8080/api/ingest/sample`
- Query graph paths: `GET http://localhost:8080/api/paths`
- Ask the agent: `POST http://localhost:8080/api/agent/ask`

## Project Structure

```
graphguard/
├── docker-compose.yml
├── pom.xml
├── README.md
├── docs/
└── src/
    ├── main/
    │   ├── java/com/graphguard/
    │   │   ├── GraphguardApplication.java
    │   │   ├── FalkorConfig.java
    │   │   ├── GraphService.java
    │   │   ├── Models.java
    │   │   ├── Ingestor.java
    │   │   ├── AnalysisService.java
    │   │   ├── AgentService.java
    │   │   └── ApiController.java
    │   └── resources/
    │       ├── application.yaml
    │       ├── sample/
    │       │   ├── iam-policies.json
    │       │   └── workflows/
    │       │       ├── deploy.yml
    │       │       ├── labeler.yml
    │       │       └── release.yml
    │       └── static/
    │           ├── index.html
    │           ├── app.js
    │           └── style.css
    └── test/
        └── java/com/graphguard/
            └── GraphGuardTest.java
```

## Design rules

- **Strict Parameterized Cypher**: Every Cypher query executed against FalkorDB uses parameters (`$param`). Dynamic interpolation is restricted exclusively to validated positive integer depths or whitelisted relationship labels.
- **Read/Write Segregation**: Graph queries that inspect topology use FalkorDB read-only connections (`readOnlyQuery` via `graphs.read`), while mutations use `graphs.write`.
- **Four Explicit Outcomes**: All tool evaluations, agent answers, and API responses categorize execution into four deterministic outcomes:
  1. `answered_with_path`: A traversal or attack path was successfully computed.
  2. `memory`: Past security decisions or audit findings were stored or retrieved.
  3. `not_in_graph`: The query target exists, but no connecting paths or reachable nodes were found.
  4. `unknown_node`: The referenced identifier does not match any node in the graph.
- **Zero Hallucination Guard**: The agent's final output is scanned for hyphenated node-like identifiers. If any identifier is absent from the verified tool execution trace, the response is discarded and replaced with factual data derived from result rows.
- **Plan-Only Remediation**: Remediation simulations run on temporary ephemeral graphs (`sim_*`) or return early if an edge does not exist, guaranteeing the main production graph is never mutated during what-if analysis.

## Demo move

See the complete 90-second judging runbook in [docs/DEMO.md](docs/DEMO.md).

Quick verification steps:
1. Start FalkorDB: `docker compose up -d`
2. Load sample graph: `curl -X POST http://localhost:8080/api/ingest/sample`
3. Inspect multi-hop attack paths: `curl http://localhost:8080/api/paths`
4. Compare blast radius at depth 1 vs 4:
   - `curl "http://localhost:8080/api/blast-radius?node=cool-org/cool-linter@v2&depth=1"` (1 node)
   - `curl "http://localhost:8080/api/blast-radius?node=cool-org/cool-linter@v2&depth=4"` (7 nodes, reaching `customer-db`)
5. Ask Copilot about non-existent nodes:
   - `curl -X POST http://localhost:8080/api/agent/ask -H "Content-Type: application/json" -d '{"question":"blast radius of payment-service"}'` (`outcome: unknown_node`, no hallucinations)

## Tests

The project includes 12 automated tests in `GraphGuardTest.java` covering:
1. Sample workflow & IAM ingestion generating 3 attack paths (3, 5, 6 hops)
2. Blast radius single-hop evaluation (depth=1)
3. Blast radius multi-hop traversal (depth=4) with deduplicated sensitive targets
4. Unknown node detection returning `outcome: unknown_node` and 0 rows
5. PageRank computation via `algo.pageRank` ranking high-centrality nodes
6. Shortest path finding via `algo.SPpaths` with hop-by-hop explanations
7. Ephemeral fix simulation on active attack path edges
8. Early-return optimization on non-existent edges
9. Audit finding persistence and recall with ISO timestamps
10. Risk acceptance decision recording and active path filtering
11. Agent guard preventing hallucinated identifiers on unknown nodes
12. Memory preservation across graph resets with automatic `relinkMemory`

Run all tests:
```powershell
.\mvnw.cmd test
```

## Known limits

- **Dynamic CI/CD Matrices**: GitHub Actions dynamic matrix generation and reusable workflows loaded from external private repositories without a token are not fully resolved.
- **Complex IAM Conditions**: IAM conditions containing wildcards, string operators, or multi-factor authentication requirements are warned and ignored rather than modeled as probabilistic edges.
- **FalkorDB Engine Prerequisite**: `readOnlyQuery` and graph algorithm procedures (`algo.pageRank`, `algo.SPpaths`) require a running FalkorDB instance supporting the graph algorithm module.

