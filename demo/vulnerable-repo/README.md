# ⚠️ INTENTIONALLY VULNERABLE REPOSITORY — FOR DEMO PURPOSES ONLY ⚠️

> [!CAUTION]
> **DO NOT USE THIS CONFIGURATION IN PRODUCTION.**
> This repository contains intentionally vulnerable GitHub Actions workflow definitions designed strictly for testing and demonstrating [GraphGuard](https://github.com/graphguard/graphguard).
>
> **NO REAL SECRETS EXIST IN THIS REPOSITORY.**
> References such as `${{ secrets.DEPLOY_TOKEN }}` are dummy placeholders only and correspond to no actual secrets, API tokens, or production credentials.

---

## Overview

This demo repository showcases how **GraphGuard** detects CI/CD and cloud supply-chain attack paths, specifically:
- **GG-CI-001**: Untrusted checkout of pull request head branch under `pull_request_target`.
- **GG-CI-002**: Direct script interpolation of untrusted `github.event` context into shell execution blocks.
- **GG-CI-003**: Privileged trigger exposure accessing secrets or write permissions.
- **GG-CI-004**: Third-party GitHub actions referenced by mutable tags instead of immutable commit SHAs.
- **GG-CI-005**: Overly permissive repository permissions (`permissions: write-all`) on sensitive triggers.
- **Safe CI Comparison**: Contrasting `safe-ci.yml` showing that secure, SHA-pinned workflows with read-only permissions are not flagged.

---

## Step-by-Step Setup: Run Your Own Live Demo Scan

To scan this repository with GraphGuard via the public GitHub API:

### 1. Create a New Public GitHub Repository
1. Log in to GitHub and navigate to [https://github.com/new](https://github.com/new).
2. Repository name: `graphguard-demo-vuln` (or any name you prefer).
3. Set visibility to **Public** (required for GraphGuard to ingest without private access tokens).
4. Do not initialize with `.gitignore` or license.
5. Click **Create repository**.

### 2. Push Demo Files to Your Repository
From your local terminal, navigate to this directory and initialize git:

```bash
cd demo/vulnerable-repo
git init -b main
git add .
git commit -m "feat: add vulnerable and safe demo workflows"
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/graphguard-demo-vuln.git
git push -u origin main
```

### 3. Scan the Repository Using GraphGuard

Ensure your GraphGuard backend is running (by default at `http://localhost:8080`).

#### Option A: Using the Demo Script
```bash
./scripts/demo.sh <YOUR_GITHUB_USERNAME>/graphguard-demo-vuln
```

#### Option B: Via Direct cURL API Ingestion
```bash
curl -s -X POST http://localhost:8080/api/ingest/github \
  -H "Content-Type: application/json" \
  -d '{"owner": "<YOUR_GITHUB_USERNAME>", "repo": "graphguard-demo-vuln"}'
```

#### Option C: View Findings and Attack Paths
```bash
# View rule findings
curl -s http://localhost:8080/api/findings

# View detected attack paths
curl -s http://localhost:8080/api/paths
```

---

## Included Workflows

1. [`.github/workflows/pr-deploy.yml`](.github/workflows/pr-deploy.yml): Intentionally vulnerable workflow demonstrating CI/CD attack paths.
2. [`.github/workflows/safe-ci.yml`](.github/workflows/safe-ci.yml): Hardened workflow with SHA pinning and minimal privileges demonstrating zero false positives.
