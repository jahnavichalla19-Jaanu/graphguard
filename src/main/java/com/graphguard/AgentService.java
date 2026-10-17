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
import com.graphguard.Models.SimResult;
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

@Service
public class AgentService {
    private static final Logger log = LoggerFactory.getLogger(AgentService.class);
    private static final Pattern HYPHENATED_NAME = Pattern.compile("\\b[A-Za-z0-9_.-]+(?:[-/@:][A-Za-z0-9_.-]+)+\\b");
    private static final String SYSTEM =
            "You are GraphGuard, a CI/CD and cloud IAM security agent backed by a FalkorDB graph database.\n" +
            "\nRULES:\n" +
            "1. Call recall before advising on any path that has an existing risk acceptance.\n" +
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

    public record ToolResult(String name, Map<String, Object> args, String outcome, int rows, long millis, Object data, List<List<String>> highlights) {}

    public ToolResult execute(String name, Map<String, Object> args) {
        long t0 = System.currentTimeMillis();
        String g = graphs.main();
        List<List<String>> highlights = new ArrayList<>();
        Map<String, Object> safeArgs = args == null ? Map.of() : args;
        try {
            switch (name) {
                case "find_attack_paths" -> {
                    List<AttackPath> ps = analysis.findPaths(g);
                    ps.forEach(p -> highlights.add(p.nodeIds()));
                    String outcome = ps.isEmpty() ? "not_in_graph" : "answered_with_path";
                    return new ToolResult(name, safeArgs, outcome, ps.size(), System.currentTimeMillis() - t0, ps, highlights);
                }
                case "blast_radius" -> {
                    String node = String.valueOf(safeArgs.getOrDefault("node", "")).trim();
                    if (node.isEmpty()) {
                        return new ToolResult(name, safeArgs, "unknown_node", 0, System.currentTimeMillis() - t0,
                                Map.of("error", "node argument is required", "outcome", "unknown_node"), highlights);
                    }
                    int depth = 4;
                    if (safeArgs.get("depth") instanceof Number n) {
                        depth = n.intValue();
                    } else if (safeArgs.get("depth") instanceof String s && !s.isBlank()) {
                        try { depth = Integer.parseInt(s); } catch (Exception ignored) {}
                    }
                    Map<String, Object> res = analysis.blastRadius(g, node, depth);
                    String outcome = String.valueOf(res.getOrDefault("outcome", "answered_with_path"));
                    int rows = res.get("rows") instanceof Number n ? n.intValue() : 0;
                    if (res.get("nodes") instanceof List<?> list) {
                        List<String> nodeIds = new ArrayList<>();
                        for (Object o : list) {
                            if (o instanceof Map<?, ?> m && m.get("id") != null) {
                                nodeIds.add(String.valueOf(m.get("id")));
                            }
                        }
                        if (!nodeIds.isEmpty()) highlights.add(nodeIds);
                    }
                    return new ToolResult(name, safeArgs, outcome, rows, System.currentTimeMillis() - t0, res, highlights);
                }
                case "path_between" -> {
                    String from = String.valueOf(safeArgs.getOrDefault("from", "")).trim();
                    String to = String.valueOf(safeArgs.getOrDefault("to", "")).trim();
                    if (from.isEmpty() || to.isEmpty()) {
                        return new ToolResult(name, safeArgs, "unknown_node", 0, System.currentTimeMillis() - t0,
                                Map.of("error", "from and to arguments are required", "outcome", "unknown_node"), highlights);
                    }
                    Map<String, Object> res = analysis.pathBetween(g, from, to);
                    String outcome = String.valueOf(res.getOrDefault("outcome", "answered_with_path"));
                    int rows = res.get("rows") instanceof Number n ? n.intValue() : 0;
                    if (res.get("nodeIds") instanceof List<?> list) {
                        List<String> ids = list.stream().map(String::valueOf).toList();
                        highlights.add(ids);
                    }
                    return new ToolResult(name, safeArgs, outcome, rows, System.currentTimeMillis() - t0, res, highlights);
                }
                case "load_bearing" -> {
                    int limit = 5;
                    if (safeArgs.get("limit") instanceof Number n) {
                        limit = n.intValue();
                    } else if (safeArgs.get("limit") instanceof String s && !s.isBlank()) {
                        try { limit = Integer.parseInt(s); } catch (Exception ignored) {}
                    }
                    Map<String, Object> res = analysis.loadBearing(g, limit);
                    int rows = res.get("rows") instanceof List<?> l ? l.size() : 0;
                    String outcome = rows > 0 ? "answered_with_path" : "not_in_graph";
                    return new ToolResult(name, safeArgs, outcome, rows, System.currentTimeMillis() - t0, res, highlights);
                }
                case "choke_points" -> {
                    Map<String, Object> res = analysis.chokePoints(g);
                    String outcome = String.valueOf(res.getOrDefault("outcome", "answered_with_path"));
                    int rows = res.get("rows") instanceof Number n ? n.intValue() : 0;
                    return new ToolResult(name, safeArgs, outcome, rows, System.currentTimeMillis() - t0, res, highlights);
                }
                case "simulate_fix" -> {
                    String source = String.valueOf(safeArgs.getOrDefault("source", "")).trim();
                    String type = String.valueOf(safeArgs.getOrDefault("type", "")).trim();
                    String target = String.valueOf(safeArgs.getOrDefault("target", "")).trim();
                    if (source.isEmpty() || type.isEmpty() || target.isEmpty()) {
                        return new ToolResult(name, safeArgs, "unknown_node", 0, System.currentTimeMillis() - t0,
                                Map.of("error", "source, type, and target arguments are required", "outcome", "unknown_node"), highlights);
                    }
                    SimResult sim = analysis.simulate(new Edge(source, type, target));
                    String outcome = sim.edgeExisted() ? "answered_with_path" : "not_in_graph";
                    return new ToolResult(name, safeArgs, outcome, 1, System.currentTimeMillis() - t0, sim, highlights);
                }
                case "recall" -> {
                    String node = String.valueOf(safeArgs.getOrDefault("node", "")).trim();
                    if (node.isEmpty()) {
                        return new ToolResult(name, safeArgs, "unknown_node", 0, System.currentTimeMillis() - t0,
                                Map.of("error", "node argument is required", "outcome", "unknown_node"), highlights);
                    }
                    Map<String, Object> res = analysis.recall(g, node);
                    String outcome = String.valueOf(res.getOrDefault("outcome", "memory"));
                    int rows = res.get("rows") instanceof Number n ? n.intValue() : 0;
                    return new ToolResult(name, safeArgs, outcome, rows, System.currentTimeMillis() - t0, res, highlights);
                }
                case "save_finding" -> {
                    String node = String.valueOf(safeArgs.getOrDefault("node", "")).trim();
                    String text = String.valueOf(safeArgs.getOrDefault("text", "")).trim();
                    if (node.isEmpty() || text.isEmpty()) {
                        return new ToolResult(name, safeArgs, "unknown_node", 0, System.currentTimeMillis() - t0,
                                Map.of("error", "node and text arguments are required", "outcome", "unknown_node"), highlights);
                    }
                    Map<String, Object> res = analysis.saveFinding(g, node, text);
                    String outcome = String.valueOf(res.getOrDefault("outcome", "memory"));
                    int rows = res.get("rows") instanceof Number n ? n.intValue() : 0;
                    return new ToolResult(name, safeArgs, outcome, rows, System.currentTimeMillis() - t0, res, highlights);
                }
                case "accept_risk" -> {
                    String pathKey = String.valueOf(safeArgs.getOrDefault("path_key", "")).trim();
                    String owner = String.valueOf(safeArgs.getOrDefault("owner", "unknown")).trim();
                    String reason = String.valueOf(safeArgs.getOrDefault("reason", "")).trim();
                    int days = 30;
                    if (safeArgs.get("days") instanceof Number n) {
                        days = n.intValue();
                    } else if (safeArgs.get("days") instanceof String s && !s.isBlank()) {
                        try { days = Integer.parseInt(s); } catch (Exception ignored) {}
                    }
                    if (pathKey.isEmpty()) {
                        return new ToolResult(name, safeArgs, "unknown_node", 0, System.currentTimeMillis() - t0,
                                Map.of("error", "path_key argument is required", "outcome", "unknown_node"), highlights);
                    }
                    analysis.acceptRisk(g, pathKey, owner, reason, days);
                    return new ToolResult(name, safeArgs, "memory", 1, System.currentTimeMillis() - t0, Map.of("status", "recorded"), highlights);
                }
                default -> {
                    return new ToolResult(name, safeArgs, "unknown_node", 0, System.currentTimeMillis() - t0,
                            Map.of("error", "Unknown tool " + name, "outcome", "unknown_node"), highlights);
                }
            }
        } catch (Exception e) {
            return new ToolResult(name, safeArgs, "unknown_node", 0, System.currentTimeMillis() - t0,
                    Map.of("error", String.valueOf(e.getMessage()), "outcome", "unknown_node"), highlights);
        }
    }

    public AgentAnswer ask(String question) {
        if (apiKey.isBlank()) {
            return fallback(question, "offline router");
        }
        try {
            return viaModel(question);
        } catch (Exception e) {
            log.warn("LLM call failed: {}", e.getMessage());
            return fallback(question, "offline router");
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
        Set<String> knownNames = new LinkedHashSet<>();
        List<ToolResult> executedResults = new ArrayList<>();
        String primaryOutcome = "answered_with_path";

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
                String sanitized = sanitize(text.toString().trim(), knownNames, executedResults);
                return new AgentAnswer(sanitized, calls, highlights, "LLM tool-calling (" + model + ")", primaryOutcome);
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
                JsonNode inputNode = b.path("input");
                Map<String, Object> input = mapper.convertValue(inputNode, new TypeReference<Map<String, Object>>() {});
                ToolResult tr = execute(name, input);
                executedResults.add(tr);
                highlights.addAll(tr.highlights());
                collectNames(tr.data(), knownNames);
                primaryOutcome = tr.outcome();

                Map<String, Object> call = new LinkedHashMap<>();
                call.put("name", name);
                call.put("args", input);
                call.put("input", input);
                call.put("rows", tr.rows());
                call.put("millis", tr.millis());
                call.put("ms", tr.millis());
                call.put("outcome", tr.outcome());
                calls.add(call);

                ObjectNode r = mapper.createObjectNode();
                r.put("type", "tool_result");
                r.put("tool_use_id", b.path("id").asText());
                r.put("content", mapper.writeValueAsString(tr.data()));
                results.add(r);
            }
            ObjectNode user = mapper.createObjectNode();
            user.put("role", "user");
            user.set("content", results);
            messages.add(user);
        }
        return new AgentAnswer("The agent stopped after too many tool calls.", calls, highlights, "LLM tool-calling (" + model + ")", primaryOutcome);
    }

    private ArrayNode tools() {
        ArrayNode a = mapper.createArrayNode();
        a.add(tool("find_attack_paths",
                "Find every path from an untrusted trigger to a sensitive secret or resource across CI/CD and IAM.",
                "{\"type\":\"object\",\"properties\":{}}"));
        a.add(tool("blast_radius",
                "List everything reachable if a node is compromised, including the shortest hop traversal path (via).",
                "{\"type\":\"object\",\"properties\":{\"node\":{\"type\":\"string\"},\"depth\":{\"type\":\"integer\",\"default\":4,\"minimum\":1,\"maximum\":6}},\"required\":[\"node\"]}"));
        a.add(tool("path_between",
                "Find shortest path between two nodes using algo.SPpaths.",
                "{\"type\":\"object\",\"properties\":{\"from\":{\"type\":\"string\"},\"to\":{\"type\":\"string\"}},\"required\":[\"from\",\"to\"]}"));
        a.add(tool("load_bearing",
                "Find most depended-on nodes using PageRank algorithm.",
                "{\"type\":\"object\",\"properties\":{\"limit\":{\"type\":\"integer\",\"default\":5}},\"required\":[]}"));
        a.add(tool("choke_points",
                "Rank single links whose removal eliminates the most active attack paths.",
                "{\"type\":\"object\",\"properties\":{}}"));
        a.add(tool("simulate_fix",
                "Simulate breaking an edge and check path impact without modifying the main graph.",
                "{\"type\":\"object\",\"properties\":{\"source\":{\"type\":\"string\"},\"type\":{\"type\":\"string\"},\"target\":{\"type\":\"string\"}},\"required\":[\"source\",\"type\",\"target\"]}"));
        a.add(tool("recall",
                "Retrieve past security decisions and recorded findings for a node.",
                "{\"type\":\"object\",\"properties\":{\"node\":{\"type\":\"string\"}},\"required\":[\"node\"]}"));
        a.add(tool("save_finding",
                "Save an audit finding attached to a node in graph memory.",
                "{\"type\":\"object\",\"properties\":{\"node\":{\"type\":\"string\"},\"text\":{\"type\":\"string\"}},\"required\":[\"node\",\"text\"]}"));
        a.add(tool("accept_risk",
                "Record a risk acceptance decision for an attack path key.",
                "{\"type\":\"object\",\"properties\":{\"path_key\":{\"type\":\"string\"},\"owner\":{\"type\":\"string\"},\"reason\":{\"type\":\"string\"},\"days\":{\"type\":\"integer\"}},\"required\":[\"path_key\"]}"));
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
        String detectedNode = extractNode(question);

        if (q.contains("between") || (q.contains("from") && q.contains("to"))) {
            String[] pair = extractFromTo(question);
            if (pair != null) {
                ToolResult tr = execute("path_between", Map.of("from", pair[0], "to", pair[1]));
                return buildFallbackAnswer(tr, mode);
            }
        }
        if (q.contains("blast") || q.contains("compromis") || q.contains("reach")) {
            String target = detectedNode != null ? detectedNode : "";
            ToolResult tr = execute("blast_radius", Map.of("node", target, "depth", 4));
            return buildFallbackAnswer(tr, mode);
        }
        if (q.contains("load") || q.contains("depend") || q.contains("pagerank")) {
            ToolResult tr = execute("load_bearing", Map.of("limit", 5));
            return buildFallbackAnswer(tr, mode);
        }
        if (q.contains("choke") || q.contains("first") || q.contains("priorit") || q.contains("most")) {
            ToolResult tr = execute("choke_points", Map.of());
            return buildFallbackAnswer(tr, mode);
        }
        if (q.contains("recall") || q.contains("history") || q.contains("decision") || q.contains("finding")) {
            String target = detectedNode != null ? detectedNode : "";
            ToolResult tr = execute("recall", Map.of("node", target));
            return buildFallbackAnswer(tr, mode);
        }

        ToolResult tr = execute("find_attack_paths", Map.of());
        return buildFallbackAnswer(tr, mode);
    }

    private AgentAnswer buildFallbackAnswer(ToolResult tr, String mode) {
        List<Map<String, Object>> calls = new ArrayList<>();
        Map<String, Object> call = new LinkedHashMap<>();
        call.put("name", tr.name());
        call.put("args", tr.args());
        call.put("input", tr.args());
        call.put("rows", tr.rows());
        call.put("millis", tr.millis());
        call.put("ms", tr.millis());
        call.put("outcome", tr.outcome());
        calls.add(call);

        String answer;
        if ("unknown_node".equals(tr.outcome())) {
            String node = String.valueOf(tr.args().getOrDefault("node", tr.args().getOrDefault("from", "")));
            answer = "Node '" + node + "' is not in the graph.";
        } else if ("not_in_graph".equals(tr.outcome())) {
            answer = "No matching paths or connections found in graph.";
        } else if ("memory".equals(tr.outcome())) {
            answer = "Recalled " + tr.rows() + " memory record(s) from graph.";
        } else {
            answer = switch (tr.name()) {
                case "find_attack_paths" -> {
                    if (tr.rows() == 0) yield "No attack paths found from untrusted triggers to sensitive targets.";
                    @SuppressWarnings("unchecked")
                    List<AttackPath> paths = (List<AttackPath>) tr.data();
                    AttackPath first = paths.get(0);
                    yield "Found " + paths.size() + " attack path(s). Shortest (" + first.length() + " hops): "
                            + String.join(" -> ", first.nodeNames()) + ". " + String.join(". ", first.explanation()) + ".";
                }
                case "blast_radius" -> {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> m = (Map<String, Object>) tr.data();
                    yield "Compromise of " + m.get("resolvedName") + " reaches " + m.get("reachableCount") + " node(s). "
                            + "Sensitive targets reached: " + m.get("sensitiveReached") + ".";
                }
                case "path_between" -> {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> m = (Map<String, Object>) tr.data();
                    yield "Path found between " + m.get("from") + " and " + m.get("to") + " (" + m.get("hops") + " hops): "
                            + String.join(" -> ", (List<String>) m.get("nodeNames")) + ".";
                }
                case "load_bearing" -> "Identified top " + tr.rows() + " most depended-on node(s) via PageRank.";
                case "choke_points" -> {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> m = (Map<String, Object>) tr.data();
                    List<?> edges = (List<?>) m.get("edges");
                    if (edges.isEmpty()) yield "There are no active attack paths to rank.";
                    RankedEdge top = (RankedEdge) edges.get(0);
                    yield "Fix first: " + top.description() + ". Breaking this link removes " + top.paths() + " attack paths.";
                }
                default -> "Executed tool " + tr.name() + " successfully with " + tr.rows() + " row(s).";
            };
        }
        return new AgentAnswer(answer, calls, tr.highlights(), mode, tr.outcome());
    }

    private String extractNode(String q) {
        Matcher m = HYPHENATED_NAME.matcher(q);
        if (m.find()) {
            return m.group();
        }
        Matcher qm = Pattern.compile("['\"]([^'\"]+)['\"]").matcher(q);
        if (qm.find()) {
            return qm.group(1);
        }
        for (String prefix : List.of("node ", "for ", "of ", "on ", "about ")) {
            int idx = q.toLowerCase(Locale.ROOT).indexOf(prefix);
            if (idx >= 0) {
                String rest = q.substring(idx + prefix.length()).trim();
                int end = rest.indexOf(' ');
                return end > 0 ? rest.substring(0, end) : rest;
            }
        }
        return null;
    }

    private String[] extractFromTo(String q) {
        int idxFrom = q.toLowerCase(Locale.ROOT).indexOf("from ");
        int idxTo = q.toLowerCase(Locale.ROOT).indexOf("to ");
        if (idxFrom >= 0 && idxTo > idxFrom) {
            String from = q.substring(idxFrom + 5, idxTo).trim();
            String to = q.substring(idxTo + 3).trim();
            int endTo = to.indexOf(' ');
            if (endTo > 0) to = to.substring(0, endTo);
            return new String[]{from, to};
        }
        int idxBetween = q.toLowerCase(Locale.ROOT).indexOf("between ");
        int idxAnd = q.toLowerCase(Locale.ROOT).indexOf(" and ");
        if (idxBetween >= 0 && idxAnd > idxBetween) {
            String from = q.substring(idxBetween + 8, idxAnd).trim();
            String to = q.substring(idxAnd + 5).trim();
            int endTo = to.indexOf(' ');
            if (endTo > 0) to = to.substring(0, endTo);
            return new String[]{from, to};
        }
        return null;
    }

    private String sanitize(String answer, Set<String> knownNames, List<ToolResult> results) {
        Matcher m = HYPHENATED_NAME.matcher(answer);
        boolean hasHallucinated = false;
        while (m.find()) {
            String candidate = m.group();
            boolean found = false;
            for (String kn : knownNames) {
                if (kn.equalsIgnoreCase(candidate) || kn.toLowerCase().contains(candidate.toLowerCase())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                hasHallucinated = true;
                break;
            }
        }
        if (!hasHallucinated) {
            return answer;
        }
        return sentenceFromRows(results);
    }

    private String sentenceFromRows(List<ToolResult> results) {
        if (results.isEmpty()) {
            return "No tool results available.";
        }
        ToolResult last = results.get(results.size() - 1);
        if ("unknown_node".equals(last.outcome())) {
            String node = String.valueOf(last.args().getOrDefault("node", last.args().getOrDefault("from", "")));
            return "Node '" + node + "' is not in the graph.";
        }
        if (last.rows() == 0) {
            return "Operation completed with 0 rows returned.";
        }
        return "Found " + last.rows() + " row(s) returned by tool " + last.name() + " (" + last.outcome() + ").";
    }

    private void collectNames(Object out, Set<String> knownNames) {
        if (out instanceof Map<?, ?> map) {
            map.forEach((k, v) -> {
                if (v instanceof String s && HYPHENATED_NAME.matcher(s).matches()) {
                    knownNames.add(s);
                } else {
                    collectNames(v, knownNames);
                }
            });
        } else if (out instanceof List<?> list) {
            list.forEach(item -> collectNames(item, knownNames));
        } else if (out instanceof AttackPath p) {
            knownNames.addAll(p.nodeIds());
            knownNames.addAll(p.nodeNames());
        } else if (out instanceof SimResult s) {
            knownNames.add(s.edge().source());
            knownNames.add(s.edge().target());
        }
    }
}