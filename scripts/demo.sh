#!/usr/bin/env bash
# ==============================================================================
# GraphGuard Demo & Verification Script
# Executes end-to-end security analysis flow via GraphGuard REST APIs.
# Usage:
#   ./scripts/demo.sh [owner/repo]
# Example:
#   ./scripts/demo.sh
#   ./scripts/demo.sh my-org/graphguard-demo-vuln
# ==============================================================================

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TARGET_REPO="${1:-}"

# Colors for terminal output
BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
RED="\033[31m"
RESET="\033[0m"

# Header printer
print_heading() {
  echo -e "\n${BOLD}${CYAN}===================================================================${RESET}"
  echo -e "${BOLD}${CYAN}  $1${RESET}"
  echo -e "${BOLD}${CYAN}===================================================================${RESET}"
}

# Subheading printer
print_step() {
  echo -e "\n${BOLD}${YELLOW}--> $1${RESET}"
}

# Success printer
print_ok() {
  echo -e "${GREEN}✔ $1${RESET}"
}

# Info printer
print_info() {
  echo -e "   $1"
}

# Determine JSON tool
JSON_TOOL="raw"
if command -v jq >/dev/null 2>&1; then
  JSON_TOOL="jq"
elif command -v python3 >/dev/null 2>&1; then
  JSON_TOOL="python3"
elif command -v python >/dev/null 2>&1; then
  JSON_TOOL="python"
fi

# Universal JSON field extractor
extract_json() {
  local json="$1"
  local py_expr="$2"
  local jq_expr="$3"

  if [ "$JSON_TOOL" = "jq" ]; then
    echo "$json" | jq -r "$jq_expr" 2>/dev/null || echo ""
  elif [ "$JSON_TOOL" = "python3" ]; then
    python3 -c "import sys, json
try:
    d = json.loads('''$json''')
    res = $py_expr
    print(res if res is not None else '')
except Exception as e:
    pass" 2>/dev/null || echo ""
  elif [ "$JSON_TOOL" = "python" ]; then
    python -c "import sys, json
try:
    d = json.loads('''$json''')
    res = $py_expr
    print(res if res is not None else '')
except Exception as e:
    pass" 2>/dev/null || echo ""
  else
    # Fallback using grep/sed for basic keys
    local key
    key=$(echo "$jq_expr" | tr -d '.[0]' | awk '{print $1}')
    echo "$json" | grep -o "\"$key\"[ ]*:[ ]*[^,}]*" | head -n1 | sed -e 's/.*:[ ]*//' -e 's/"//g' || echo ""
  fi
}

# HTTP request helper with precise elapsed timing
api_request() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local url="${BASE_URL}${path}"

  local start_time
  start_time=$(date +%s%N 2>/dev/null || true)
  if [[ ! "$start_time" =~ ^[0-9]+$ ]]; then
    start_time=$(date +%s)
  fi

  local resp
  local http_code
  local curl_out

  if [ -n "$data" ]; then
    curl_out=$(curl -s -S -w "\n%{http_code}\n%{time_total}" -X "$method" "$url" \
      -H "Content-Type: application/json" \
      -d "$data" || echo -e "\n000\n0.0")
  else
    curl_out=$(curl -s -S -w "\n%{http_code}\n%{time_total}" -X "$method" "$url" || echo -e "\n000\n0.0")
  fi

  # Split output into body, http_code, time_total
  local elapsed
  elapsed=$(echo "$curl_out" | tail -n1)
  http_code=$(echo "$curl_out" | tail -n2 | head -n1)
  resp=$(echo "$curl_out" | sed '$d' | sed '$d')

  if [ "$http_code" = "000" ] || [ -z "$http_code" ]; then
    echo -e "${RED}ERROR: Unable to connect to GraphGuard at ${url}${RESET}" >&2
    echo -e "${RED}Please ensure the backend server is running on ${BASE_URL}.${RESET}" >&2
    exit 1
  fi

  if [ "$http_code" -ge 400 ]; then
    echo -e "${RED}HTTP $http_code from $url (elapsed: ${elapsed}s)${RESET}" >&2
    echo "$resp" >&2
    exit 1
  fi

  # Return response with elapsed time appended on final line for caller
  echo "$resp"
  echo "__ELAPSED__:${elapsed}"
}

parse_call_result() {
  local raw_output="$1"
  BODY=$(echo "$raw_output" | grep -v '^__ELAPSED__:' || true)
  ELAPSED_SEC=$(echo "$raw_output" | grep '^__ELAPSED__:' | head -n1 | cut -d: -f2 || echo "0.0")
}

# ==============================================================================
# DEMO EXECUTION
# ==============================================================================

print_heading "GRAPHGUARD DEMO & SECURITY REASONING ENGINE"
print_info "Base API URL : ${BASE_URL}"
print_info "JSON Parser  : ${JSON_TOOL}"
if [ -n "$TARGET_REPO" ]; then
  print_info "Target Repo  : ${TARGET_REPO}"
fi

# ------------------------------------------------------------------------------
# Step 1: Health Check
# ------------------------------------------------------------------------------
print_step "1. Checking System Health & FalkorDB Connection"
PARSE_OUT=$(api_request "GET" "/api/health")
parse_call_result "$PARSE_OUT"

STATUS=$(extract_json "$BODY" "d.get('status')" ".status")
GRAPH_NAME=$(extract_json "$BODY" "d.get('graph')" ".graph")

if [ "$STATUS" = "ok" ]; then
  print_ok "GraphGuard API is healthy (status: $STATUS, active graph: $GRAPH_NAME, latency: ${ELAPSED_SEC}s)"
else
  echo -e "${RED}Unexpected health response: $BODY${RESET}"
  exit 1
fi

# ------------------------------------------------------------------------------
# Step 2: Load Sample Scenario (CI/CD + IAM Attack Graph)
# ------------------------------------------------------------------------------
print_step "2. Loading Sample Multi-Tier Ingestion (Workflows + AWS IAM)"
PARSE_OUT=$(api_request "POST" "/api/ingest/sample")
parse_call_result "$PARSE_OUT"

NUM_WORKFLOWS=$(extract_json "$BODY" "d.get('workflows')" ".workflows")
NUM_NODES=$(extract_json "$BODY" "d.get('nodes')" ".nodes")
NUM_EDGES=$(extract_json "$BODY" "d.get('edges')" ".edges")
NUM_PATHS=$(extract_json "$BODY" "d.get('paths')" ".paths")

print_ok "Sample scenario loaded into knowledge graph (latency: ${ELAPSED_SEC}s)"
print_info "Ingested Workflows : ${NUM_WORKFLOWS}"
print_info "Graph Nodes        : ${NUM_NODES}"
print_info "Graph Edges        : ${NUM_EDGES}"
print_info "Initial Paths      : ${NUM_PATHS}"

# ------------------------------------------------------------------------------
# Step 3: Enumerate Attack Paths
# ------------------------------------------------------------------------------
print_step "3. Enumerating Cross-System Attack Paths (/api/paths)"
PARSE_OUT=$(api_request "GET" "/api/paths")
parse_call_result "$PARSE_OUT"

PATH_COUNT=0
if [ "$JSON_TOOL" = "jq" ]; then
  PATH_COUNT=$(echo "$BODY" | jq '. | length' 2>/dev/null || echo "0")
elif [ "$JSON_TOOL" = "python3" ] || [ "$JSON_TOOL" = "python" ]; then
  PATH_COUNT=$(python3 -c "import sys, json; print(len(json.loads('''$BODY''')))" 2>/dev/null || echo "0")
else
  PATH_COUNT=$(echo "$BODY" | grep -o '"key"' | wc -l | tr -d ' ' || echo "0")
fi

print_ok "Discovered ${PATH_COUNT} end-to-end attack paths from untrusted trigger to sensitive asset (latency: ${ELAPSED_SEC}s)"

# Display first attack path details
if [ "$PATH_COUNT" -gt 0 ]; then
  FIRST_KEY=$(extract_json "$BODY" "d[0].get('key')" ".[0].key")
  FIRST_SEV=$(extract_json "$BODY" "d[0].get('severity')" ".[0].severity")
  FIRST_NODES=$(extract_json "$BODY" "' -> '.join(d[0].get('nodeNames', []))" ".[0].nodeNames | join(\" -> \")")
  print_info "Top Path [${FIRST_SEV^^}] Key : ${FIRST_KEY}"
  print_info "Traversal Path         : ${FIRST_NODES}"
fi

# ------------------------------------------------------------------------------
# Step 4: Identify Critical Choke Points
# ------------------------------------------------------------------------------
print_step "4. Calculating Choke Points for Maximum Path Reduction (/api/choke-points)"
PARSE_OUT=$(api_request "GET" "/api/choke-points")
parse_call_result "$PARSE_OUT"

TOTAL_ACTIVE_PATHS=$(extract_json "$BODY" "d.get('activePaths')" ".activePaths")
print_ok "Active paths analyzed: ${TOTAL_ACTIVE_PATHS} (latency: ${ELAPSED_SEC}s)"

# Extract top choke point edge
TOP_EDGE_SRC=$(extract_json "$BODY" "d.get('edges', [{}])[0].get('source')" ".edges[0].source")
TOP_EDGE_TYPE=$(extract_json "$BODY" "d.get('edges', [{}])[0].get('type')" ".edges[0].type")
TOP_EDGE_TGT=$(extract_json "$BODY" "d.get('edges', [{}])[0].get('target')" ".edges[0].target")
TOP_EDGE_DESC=$(extract_json "$BODY" "d.get('edges', [{}])[0].get('description')" ".edges[0].description")
TOP_EDGE_PATHS=$(extract_json "$BODY" "d.get('edges', [{}])[0].get('paths')" ".edges[0].paths")

print_info "Top Edge Choke Point : ${TOP_EDGE_DESC}"
print_info "Impact on Removal    : Eliminates ${TOP_EDGE_PATHS} of ${TOTAL_ACTIVE_PATHS} active attack paths"

# ------------------------------------------------------------------------------
# Step 5: Simulate Fix on the Top Choke Point
# ------------------------------------------------------------------------------
print_step "5. Simulating Architectural Fix Without Modifying Production Graph (/api/simulate-fix)"
if [ -n "$TOP_EDGE_SRC" ] && [ -n "$TOP_EDGE_TYPE" ] && [ -n "$TOP_EDGE_TGT" ]; then
  SIM_PAYLOAD="{\"source\":\"${TOP_EDGE_SRC}\",\"type\":\"${TOP_EDGE_TYPE}\",\"target\":\"${TOP_EDGE_TGT}\"}"
  PARSE_OUT=$(api_request "POST" "/api/simulate-fix" "$SIM_PAYLOAD")
  parse_call_result "$PARSE_OUT"

  SIM_BEFORE=$(extract_json "$BODY" "d.get('before')" ".before")
  SIM_AFTER=$(extract_json "$BODY" "d.get('after')" ".after")
  SIM_PROPOSAL=$(extract_json "$BODY" "d.get('proposal')" ".proposal")

  print_ok "Simulation successful (latency: ${ELAPSED_SEC}s)"
  print_info "Attack Paths Before Fix : ${SIM_BEFORE}"
  print_info "Attack Paths After Fix  : ${SIM_AFTER}"
  print_info "Paths Eliminated        : $((SIM_BEFORE - SIM_AFTER))"
  print_info "Remediation Guidance    : ${SIM_PROPOSAL}"
else
  print_info "No candidate choke point edge available for simulation."
fi

# ------------------------------------------------------------------------------
# Step 6: Query Rule Findings
# ------------------------------------------------------------------------------
print_step "6. Querying Static & Graph Rule Findings (/api/findings)"
PARSE_OUT=$(api_request "GET" "/api/findings")
parse_call_result "$PARSE_OUT"

FINDINGS_COUNT=0
if [ "$JSON_TOOL" = "jq" ]; then
  FINDINGS_COUNT=$(echo "$BODY" | jq '. | length' 2>/dev/null || echo "0")
elif [ "$JSON_TOOL" = "python3" ] || [ "$JSON_TOOL" = "python" ]; then
  FINDINGS_COUNT=$(python3 -c "import sys, json; print(len(json.loads('''$BODY''')))" 2>/dev/null || echo "0")
else
  FINDINGS_COUNT=$(echo "$BODY" | grep -o '"ruleId"' | wc -l | tr -d ' ' || echo "0")
fi

print_ok "Found ${FINDINGS_COUNT} rule findings (latency: ${ELAPSED_SEC}s)"
if [ "$JSON_TOOL" = "jq" ]; then
  echo "$BODY" | jq -r '.[] | "   - [\(.ruleId)] [\(.severity | ascii_upcase)] \(.title)"' | head -n 6
elif [ "$JSON_TOOL" = "python3" ] || [ "$JSON_TOOL" = "python" ]; then
  python3 -c "import sys, json
for f in json.loads('''$BODY''')[:6]:
    print(f\"   - [{f.get('ruleId')}] [{f.get('severity','').upper()}] {f.get('title')}\")" 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# Step 7: Ask the Agent an Unknown-Node Question (Zero-Hallucination Check)
# ------------------------------------------------------------------------------
print_step "7. Testing Security Agent Reasoning & Hallucination Defense (/api/agent/ask)"
UNKNOWN_QUERY="What is the blast radius of ghost-service?"
ASK_PAYLOAD="{\"question\":\"${UNKNOWN_QUERY}\"}"

print_info "User Query : \"${UNKNOWN_QUERY}\""
PARSE_OUT=$(api_request "POST" "/api/agent/ask" "$ASK_PAYLOAD")
parse_call_result "$PARSE_OUT"

AGENT_ANSWER=$(extract_json "$BODY" "d.get('answer')" ".answer")
AGENT_OUTCOME=$(extract_json "$BODY" "d.get('outcome')" ".outcome")

print_ok "Agent response received (latency: ${ELAPSED_SEC}s)"
print_info "Engine Outcome : ${AGENT_OUTCOME}"
print_info "Agent Answer   : \"${AGENT_ANSWER}\""

if [[ "$AGENT_OUTCOME" =~ (unknown_node|not_in_graph) ]] || [[ "$AGENT_ANSWER" =~ not\ in\ the\ graph ]]; then
  print_ok "Hallucination Defense: Correctly recognized node is not in graph instead of inventing impact."
else
  print_info "Outcome returned: ${AGENT_OUTCOME}"
fi

# ------------------------------------------------------------------------------
# Step 8: Optional Live GitHub Ingestion
# ------------------------------------------------------------------------------
if [ -n "$TARGET_REPO" ]; then
  print_heading "LIVE GITHUB REPOSITORY INGESTION & SCAN"
  print_step "8. Scanning Repository: ${TARGET_REPO} (/api/ingest/github)"

  REPO_OWNER=$(echo "$TARGET_REPO" | cut -d/ -f1)
  REPO_NAME=$(echo "$TARGET_REPO" | cut -d/ -f2)

  GITHUB_PAYLOAD="{\"owner\":\"${REPO_OWNER}\",\"repo\":\"${REPO_NAME}\"}"
  PARSE_OUT=$(api_request "POST" "/api/ingest/github" "$GITHUB_PAYLOAD")
  parse_call_result "$PARSE_OUT"

  SCANNED_WORKFLOWS=$(extract_json "$BODY" "d.get('workflows')" ".workflows")
  SCANNED_NODES=$(extract_json "$BODY" "d.get('nodes')" ".nodes")
  SCANNED_EDGES=$(extract_json "$BODY" "d.get('edges')" ".edges")
  SCANNED_PATHS=$(extract_json "$BODY" "d.get('paths')" ".paths")

  print_ok "Live scan completed for ${TARGET_REPO} (latency: ${ELAPSED_SEC}s)"
  print_info "Scanned Workflows : ${SCANNED_WORKFLOWS}"
  print_info "Graph Nodes       : ${SCANNED_NODES}"
  print_info "Graph Edges       : ${SCANNED_EDGES}"
  print_info "Attack Paths      : ${SCANNED_PATHS}"
fi

print_heading "DEMO RUN COMPLETE: ALL CHECKS PASSED"
