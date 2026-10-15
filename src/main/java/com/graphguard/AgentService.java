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
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Service
public class AgentService {
    private static final Logger log = LoggerFactory.getLogger(AgentService.class);
    private static final String SYSTEM = "You are GraphGuard, a security analysis agent for a graph that joins GitHub Actions pipelines and cloud IAM. "
            + "Answer ONLY from tool results and never invent nodes, paths or permissions. Call a tool before answering any question about attack paths, exposure or fixes. "
            + "Write paths as name1 -> name2 -> name3. Remediation is plan-only: never claim you changed anything. If a tool returns nothing, say so. Keep answers under 150 words.";

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
                return new AgentAnswer(text.toString().trim(), calls, highlights, "LLM tool-calling (" + model + ")");
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
                case "blast_radius" -> analysis.blastRadius(g, in.path("node").asText());
                case "choke_points" -> analysis.chokePoints(g);
                case "simulate_fix" -> analysis.simulate(new Edge(in.path("source").asText(), in.path("type").asText(), in.path("target").asText()));
                case "accept_risk" -> {
                    analysis.acceptRisk(g, in.path("path_key").asText(), in.path("owner").asText("unknown"), in.path("reason").asText(""), in.path("days").asInt(30));
                    yield Map.of("status", "recorded");
                }
                default -> Map.of("error", "unknown tool " + name);
            };
        } catch (Exception e) {
            return Map.of("error", String.valueOf(e.getMessage()));
        }
    }

    private ArrayNode tools() {
        ArrayNode a = mapper.createArrayNode();
        a.add(tool("find_attack_paths", "Find every path from an untrusted trigger (fork pull request, issue comment) to a sensitive secret or resource across the CI/CD and IAM graph.",
                "{\"type\":\"object\",\"properties\":{}}"));
        a.add(tool("blast_radius", "List everything reachable if a node is compromised. Accepts a node id or part of its name, for example cool-linter.",
                "{\"type\":\"object\",\"properties\":{\"node\":{\"type\":\"string\"}},\"required\":[\"node\"]}"));
        a.add(tool("choke_points", "Rank the single links and nodes whose removal breaks the most attack paths. Use for what to fix first.",
                "{\"type\":\"object\",\"properties\":{}}"));
        a.add(tool("simulate_fix", "Remove one edge in a temporary copy of the graph and re-run the path search. Returns paths before and after, plus a plan-only remediation text.",
                "{\"type\":\"object\",\"properties\":{\"source\":{\"type\":\"string\"},\"type\":{\"type\":\"string\"},\"target\":{\"type\":\"string\"}},\"required\":[\"source\",\"type\",\"target\"]}"));
        a.add(tool("accept_risk", "Record an accepted risk for a path key with an owner, reason and expiry in days.",
                "{\"type\":\"object\",\"properties\":{\"path_key\":{\"type\":\"string\"},\"owner\":{\"type\":\"string\"},\"reason\":{\"type\":\"string\"},\"days\":{\"type\":\"integer\"}},\"required\":[\"path_key\",\"owner\",\"reason\"]}"));
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
}