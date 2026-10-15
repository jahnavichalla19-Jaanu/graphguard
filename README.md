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
```
