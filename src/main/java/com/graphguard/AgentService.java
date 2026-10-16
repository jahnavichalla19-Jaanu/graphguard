package com.graphguard;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.graphguard.Models.AgentAnswer;
import com.graphguard.Models.AttackPath;
import com.graphguard.Models.Edge;
import com.graphguard.Models.RankedEdge;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class AgentService {
    private static final Logger log = LoggerFactory.getLogger(AgentService.class);
    private static final Pattern NODE_ID = Pattern.compile("\\b[a-z][a-z0-9]*(?:[-:][a-z0-9]+)+\\b");
    private static final String SYSTEM =
            "You are GraphGuard, a CI/CD and cloud IAM security agent backed by a FalkorDB graph database.\n" +
            "\nRULES:\n" +
            "1. Call recall_decisions before advising on any path that has an existing risk acceptance.\n" +
            "2. Call a tool before answering ANY question about attack paths, blast radius, exposure, or fixes.\n" +
            "3. When a blast_radius or find_attack_paths result is empty, say exactly that \u2014 do NOT infer impact.\n" +
            "4. Write paths as: name1 -> name2 -> name3 showing every hop returned in the 'via' field.\n" +
            "5. Never invent node names, role names, secret names, or resource names. Only use names returned by tools.\n" +
            "6. If a node is not found (outcome=unknown_node), say 'this node is not in the graph' and stop.\n" +
            "7. Remediation is plan-only: never claim you changed anything.\n" +
            "8. Show the tool trace that led to each answer so it can be audited.\n" +
            "9. Keep answers under 200 words. Prefer bullet lists with one hop per bullet.\n" +
            "10. When paths exist at depth=1 but more appear at depth=4, explicitly highlight the deeper discoveries as 'found through graph traversal.'";

    private final GraphService graphs;
    private final AnalysisService analysis;
    private final ObjectMapper mapper = new ObjectMapper();
    private final RestClient http = RestClient.create();
    private final String apiKey;
    private final String model;

    public AgentService(GraphService graphs, AnalysisService analysis,
                        @Value("${anthropic.api-key:}") String apiKey, @Value("${anthropic.model}") String model) {
        this.graphs = graphs;
        this.analysis = analysis;
        this.apiKey = apiKey;
        this.model = model;
    }

    public AgentAnswer ask(String question) {
        if (apiKey.isBlank()) {
            return fallback(question, "offline router (no ANTHROPIC_API_KEY set)");
        }
        try {
            return viaModel(question);
        } catch (Exception e) {
            log.warn("LLM call failed: {}", e.getMessage());
            return fallback(question, "offline router (LLM call failed)");
        }
    }

    private AgentAnswer viaModel(String question) throws JsonProcessingException {
        ArrayNode messages = mapper.createArrayNode();
        ObjectNode first = mapper.createObjectNode();
        first.put("role", "user");
        first.put("content", question);
        messages.add(first);
        List<Map<String, Object>> calls = new ArrayList<>();
        List<List<String>> highlights = new ArrayList<>();
        Set<String> knownIds = new LinkedHashSet<>();
        for (int turn = 0; turn < 6; turn++) {
            ObjectNode body = mapper.createObjectNode();
            body.put("model", model);
            body.put("max_tokens", 1500);
            body.put("system", SYSTEM);
            body.set("tools", tools());
            body.set("messages", messages);
            String raw = http.post().uri("https://api.anthropic.com/v1/messages")
                    .header("x-api-key", apiKey)
                    .header("anthropic-version", "2023-06-01")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(mapper.writeValueAsString(body))
                    .retrieve().body(String.class);
            JsonNode res = mapper.readTree(raw);
            JsonNode content = res.path("content");
            if (!"tool_use".equals(res.path("stop_reason").asText())) {
                StringBuilder text = new StringBuilder();
                for (JsonNode b : content) {
                    if ("text".equals(b.path("type").asText())) {
                        text.append(b.path("text").asText());
                    }
                }
                return new AgentAnswer(sanitize(text.toString().trim(), knownIds), calls, highlights, "LLM tool-calling (" + model + ")");
            }
            ObjectNode assistant = mapper.createObjectNode();
            assistant.put("role", "assistant");
            assistant.set("content", content);
            messages.add(assistant);
            ArrayNode results = mapper.createArrayNode();
            for (JsonNode b : content) {
                if (!"tool_use".equals(b.path("type").asText())) {
                    continue;
                }
                String name = b.path("name").asText();
                JsonNode input = b.path("input");
                Object out = runTool(name, input, highlights);
                collectIds(out, knownIds);
                Map<String, Object> call = new LinkedHashMap<>();
                call.put("name", name);
                call.put("input", mapper.convertValue(input, new TypeReference<Map<String, Object>>() {}));
                calls.add(call);
                ObjectNode r = mapper.createObjectNode();
                r.put("type", "tool_result");
                r.put("tool_use_id", b.path("id").asText());
                r.put("content", mapper.writeValueAsString(out));
                results.add(r);
            }
            ObjectNode user = mapper.createObjectNode();
            user.put("role", "user");
            user.set("content", results);
            messages.add(user);
        }
        return new AgentAnswer("The agent stopped after too many tool calls.", calls, highlights, "LLM tool-calling (" + model + ")");
    }

    private Object runTool(String name, JsonNode in, List<List<String>> highlights) {
        try {
            String g = graphs.main();
            return switch (name) {
                case "find_attack_paths" -> {
                    List<AttackPath> ps = analysis.findPaths(g);
                    ps.forEach(p -> highlights.add(p.nodeIds()));
                    yield ps;
                }
                case "blast_radius" -> {
                    String nodeQuery = in.path("node").asText();
                    int depth = in.has("depth") ? Math.min(Math.max(in.path("depth").asInt(4), 1), 6) : 4;
                    String resolved = analysis.resolveNode(g, nodeQuery);
                    if (resolved == null) {
                        yield Map.of("outcome", "unknown_node", "tried", nodeQuery,
                                "message", "No node matching '" + nodeQuery + "' exists in the graph. Check spelling or load data first.");
                    }
                    yield analysis.blastRadius(g, resolved, depth);
                }
                case "choke_points" -> analysis.chokePoints(g);
                case "simulate_fix" -> analysis.simulate(new Edge(in.path("source").asText(), in.path("type").asText(), in.path("target").asText()));
                case "accept_risk" -> {
                    analysis.acceptRisk(g, in.path("path_key").asText(), in.path("owner").asText("unknown"), in.path("reason").asText(""), in.path("days").asInt(30));
                    yield Map.of("status", "recorded");
                }
                case "recall_decisions" -> {
                    String target = in.path("node_or_path").asText();
                    yield graphs.query(g,
                            "MATCH (d:Decision)-[:APPLIES_TO]->(n) " +
                            "WHERE toLower(n.name) CONTAINS toLower($t) OR d.id = $t " +
                            "RETURN d.id AS pathKey, d.owner AS owner, d.reason AS reason, " +
                            "       d.expiresAt AS expiresAt, n.name AS appliesTo",
                            Map.of("t", target));
                }
                default -> Map.of("error", "unknown tool " + name);
            };
        } catch (Exception e) {
            return Map.of("error", String.valueOf(e.getMessage()));
        }
    }

    private ArrayNode tools() {
        ArrayNode a = mapper.createArrayNode();
        a.add(tool("find_attack_paths",
                "Find every path from an untrusted trigger (fork pull request, issue comment) to a sensitive secret or resource across the CI/CD and IAM graph.",
                "{\"type\":\"object\",\"properties\":{}}"));
        a.add(tool("blast_radius",
                "List everything reachable if a node is compromised, including the traversal path (via) to each reachable node. Accepts a node id or part of its name. Use depth=1 for immediate neighbours, depth=4 for deep discovery. If outcome=unknown_node is returned, the node does not exist in the graph.",
                "{\"type\":\"object\",\"properties\":{\"node\":{\"type\":\"string\"},\"depth\":{\"type\":\"integer\",\"default\":4,\"minimum\":1,\"maximum\":6}},\"required\":[\"node\"]}"));
        a.add(tool("choke_points",
                "Rank the single links and nodes whose removal breaks the most attack paths. Use for what to fix first.",
                "{\"type\":\"object\",\"properties\":{}}"));
        a.add(tool("simulate_fix",
                "Remove one edge in a temporary copy of the graph and re-run the path search. Returns paths before and after, plus a plan-only remediation text.",
                "{\"type\":\"object\",\"properties\":{\"source\":{\"type\":\"string\"},\"type\":{\"type\":\"string\"},\"target\":{\"type\":\"string\"}},\"required\":[\"source\",\"type\",\"target\"]}"));
        a.add(tool("accept_risk",
                "Record an accepted risk for a path key with an owner, reason and expiry in days.",
                "{\"type\":\"object\",\"properties\":{\"path_key\":{\"type\":\"string\"},\"owner\":{\"type\":\"string\"},\"reason\":{\"type\":\"string\"},\"days\":{\"type\":\"integer\"}},\"required\":[\"path_key\",\"owner\",\"reason\"]}"));
        a.add(tool("recall_decisions",
                "Return previously accepted risks and decisions for a specific attack path or node. Always call this before advising on a path to check if it is already acknowledged.",
                "{\"type\":\"object\",\"properties\":{\"node_or_path\":{\"type\":\"string\"}},\"required\":[\"node_or_path\"]}"));
        return a;
    }


    private ObjectNode tool(String name, String description, String schema) {
        try {
            ObjectNode t = mapper.createObjectNode();
            t.put("name", name);
            t.put("description", description);
            t.set("input_schema", mapper.readTree(schema));
            return t;
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private AgentAnswer fallback(String question, String mode) {
        String q = question.toLowerCase(Locale.ROOT);
        String g = graphs.main();
        List<Map<String, Object>> calls = new ArrayList<>();
        List<List<String>> highlights = new ArrayList<>();
        if (q.contains("choke") || q.contains("first") || q.contains("priorit") || q.contains("most")) {
            Map<String, Object> c = analysis.chokePoints(g);
            calls.add(Map.of("name", "choke_points", "input", Map.of()));
            List<?> edges = (List<?>) c.get("edges");
            if (edges.isEmpty()) {
                return new AgentAnswer("There are no active attack paths to rank.", calls, highlights, mode);
            }
            RankedEdge top = (RankedEdge) edges.get(0);
            return new AgentAnswer("Fix first: " + top.description() + ". Breaking this one link removes " + top.paths() + " of "
                    + c.get("activePaths") + " active attack paths.", calls, highlights, mode);
        }
        if (q.contains("blast") || q.contains("compromis")) {
            return new AgentAnswer("Click any node in the graph to see its blast radius, or set ANTHROPIC_API_KEY to ask in natural language.", calls, highlights, mode);
        }
        List<AttackPath> paths = analysis.findPaths(g);
        calls.add(Map.of("name", "find_attack_paths", "input", Map.of()));
        paths.forEach(p -> highlights.add(p.nodeIds()));
        if (paths.isEmpty()) {
            return new AgentAnswer("No path from an untrusted trigger to a sensitive target was found.", calls, highlights, mode);
        }
        AttackPath first = paths.get(0);
        return new AgentAnswer("Found " + paths.size() + " attack path(s). Shortest (" + first.length() + " hops): "
                + String.join(" -> ", first.nodeNames()) + ". " + String.join(". ", first.explanation()) + ".", calls, highlights, mode);
    }

    /**
     * Scans the LLM's final answer for node-ID-shaped tokens and warns if any were
     * not returned by any tool call in this session. This is the programmatic guard
     * against hallucinated node names (Gap 5).
     */
    private String sanitize(String answer, Set<String> knownIds) {
        if (knownIds.isEmpty()) return answer;
        Matcher m = NODE_ID.matcher(answer);
        Set<String> invented = new LinkedHashSet<>();
        while (m.find()) {
            String candidate = m.group();
            if (!knownIds.contains(candidate)) {
                invented.add(candidate);
            }
        }
        if (!invented.isEmpty()) {
            log.warn("LLM referenced identifiers not returned by any tool: {}", invented);
            return answer + "\n\n\u26a0\ufe0f Note: the following identifiers could not be verified against graph tool results: "
                    + invented.stream().sorted().collect(Collectors.joining(", ")) + ".";
        }
        return answer;
    }

    /**
     * Recursively extracts string values from tool output that look like node IDs
     * and adds them to the known-IDs set for the sanitize() check.
     */
    @SuppressWarnings("unchecked")
    private void collectIds(Object out, Set<String> knownIds) {
        if (out instanceof Map<?, ?> map) {
            map.forEach((k, v) -> {
                if (v instanceof String s && NODE_ID.matcher(s).matches()) knownIds.add(s);
                else collectIds(v, knownIds);
            });
        } else if (out instanceof List<?> list) {
            list.forEach(item -> collectIds(item, knownIds));
        }
    }
}