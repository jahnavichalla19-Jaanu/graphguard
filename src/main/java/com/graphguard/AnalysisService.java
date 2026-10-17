package com.graphguard;

import com.graphguard.Models.AttackPath;
import com.graphguard.Models.Edge;
import com.graphguard.Models.RankedEdge;
import com.graphguard.Models.RankedNode;
import com.graphguard.Models.SimResult;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class AnalysisService {
    private static final Set<String> EDGE_TYPES = Set.of("HAS_WORKFLOW", "FIRES", "RUNS_JOB", "RUNS_IN", "CAN_READ", "ASSUMES",
            "CAN_ASSUME", "CAN_PASS_ROLE", "CAN_UPDATE_CODE", "EXECUTES_AS", "CAN_ACCESS");
    private static final String EDGE_TYPES_JOINED = String.join("|", EDGE_TYPES);
    private static final String PATH_QUERY = """
            MATCH p = (t:Trigger {untrusted: true})-[*1..8]->(r)
            WHERE r.sensitive = true
            RETURN [n IN nodes(p) | n.id] AS ids,
                   [n IN nodes(p) | n.name] AS names,
                   [n IN nodes(p) | labels(n)[0]] AS labels,
                   [x IN relationships(p) | type(x)] AS types
            """;

    private final GraphService graphs;
    private final Ingestor ingestor;

    public AnalysisService(GraphService graphs, Ingestor ingestor) {
        this.graphs = graphs;
        this.ingestor = ingestor;
    }

    public record ResolvedNode(String id, String name, String label, boolean found, String message, List<String> candidates) {}

    public ResolvedNode resolve(String graph, String text) {
        if (text == null || text.isBlank()) {
            return new ResolvedNode(null, null, null, false, "Node name cannot be blank.", List.of());
        }
        String trimmed = text.trim();
        List<Map<String, Object>> all = graphs.read(graph,
                "MATCH (n) WHERE NOT 'Decision' IN labels(n) AND NOT 'Finding' IN labels(n) RETURN n.id AS id, n.name AS name, labels(n)[0] AS label",
                Map.of());
        if (all.isEmpty()) {
            return new ResolvedNode(null, null, null, false, "No nodes loaded in graph.", List.of());
        }
        for (Map<String, Object> r : all) {
            String id = String.valueOf(r.get("id"));
            String name = String.valueOf(r.get("name"));
            if (id.equals(trimmed) || name.equalsIgnoreCase(trimmed)) {
                return new ResolvedNode(id, name, String.valueOf(r.get("label")), true, null, List.of());
            }
        }
        String lower = trimmed.toLowerCase();
        List<Map<String, Object>> partials = new ArrayList<>();
        for (Map<String, Object> r : all) {
            String id = String.valueOf(r.get("id")).toLowerCase();
            String name = String.valueOf(r.get("name")).toLowerCase();
            if (id.contains(lower) || name.contains(lower)) {
                partials.add(r);
            }
        }
        if (partials.size() == 1) {
            Map<String, Object> m = partials.get(0);
            return new ResolvedNode(String.valueOf(m.get("id")), String.valueOf(m.get("name")), String.valueOf(m.get("label")), true, null, List.of());
        }
        List<String> candidates = new ArrayList<>();
        if (partials.size() > 1) {
            for (Map<String, Object> r : partials) {
                candidates.add(String.valueOf(r.get("name")));
                if (candidates.size() >= 5) break;
            }
            return new ResolvedNode(null, null, null, false, "Multiple nodes match '" + trimmed + "'. Did you mean: " + String.join(", ", candidates) + "?", candidates);
        }
        for (Map<String, Object> r : all) {
            String name = String.valueOf(r.get("name"));
            candidates.add(name);
            if (candidates.size() >= 5) break;
        }
        return new ResolvedNode(null, null, null, false, "No node matching '" + trimmed + "' found in graph. Did you mean: " + String.join(", ", candidates) + "?", candidates);
    }

    public String resolveNode(String graph, String query) {
        ResolvedNode r = resolve(graph, query);
        return r.found() ? r.id() : null;
    }

    public List<AttackPath> findPaths(String graph) {
        Map<String, String> accepted = activeDecisions(graph);
        Map<String, AttackPath> unique = new LinkedHashMap<>();
        for (Map<String, Object> row : graphs.read(graph, PATH_QUERY, Map.of())) {
            List<String> ids = strings(row.get("ids"));
            List<String> names = strings(row.get("names"));
            List<String> labels = strings(row.get("labels"));
            List<String> types = strings(row.get("types"));
            String key = key(ids, types);
            if (unique.containsKey(key)) {
                continue;
            }
            List<String> explanation = new ArrayList<>();
            for (int i = 0; i < types.size(); i++) {
                explanation.add(sentence(types.get(i), names.get(i), names.get(i + 1)));
            }
            unique.put(key, new AttackPath(key, types.size(), ids, names, labels, types, explanation,
                    accepted.containsKey(key), accepted.getOrDefault(key, "")));
        }
        return unique.values().stream()
                .sorted(Comparator.comparingInt(AttackPath::length).thenComparing(AttackPath::key))
                .toList();
    }

    public Map<String, Object> graph(String graph) {
        List<Map<String, Object>> nodes = graphs.read(graph, """
                MATCH (n) WHERE NOT 'Decision' IN labels(n) AND NOT 'Finding' IN labels(n)
                RETURN n.id AS id, n.name AS name, labels(n)[0] AS label, n.sensitive AS sensitive, n.untrusted AS untrusted, n.pinned AS pinned
                """, Map.of());
        List<Map<String, Object>> edges = graphs.read(graph, """
                MATCH (a)-[r]->(b) WHERE NOT 'Decision' IN labels(a) AND NOT 'Finding' IN labels(a)
                  AND NOT 'Decision' IN labels(b) AND NOT 'Finding' IN labels(b)
                RETURN a.id AS source, b.id AS target, type(r) AS type
                """, Map.of());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("nodes", nodes);
        out.put("edges", edges);
        return out;
    }

    public Map<String, Object> blastRadius(String graph, String text, int depth) {
        long t0 = System.currentTimeMillis();
        int cap = Math.min(Math.max(depth, 1), 6);
        ResolvedNode res = resolve(graph, text);
        if (!res.found()) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("outcome", "unknown_node");
            out.put("query", text);
            out.put("depth", cap);
            out.put("reachableCount", 0);
            out.put("rows", 0);
            out.put("byLabel", Map.of());
            out.put("sensitiveReached", List.of());
            out.put("sensitive", List.of());
            out.put("byDepth", Map.of());
            out.put("nodes", List.of());
            out.put("message", res.message());
            out.put("millis", System.currentTimeMillis() - t0);
            return out;
        }
        List<Map<String, Object>> rawRows = graphs.read(graph,
                "MATCH p = (s)-[*1.." + cap + "]->(x) " +
                "WHERE s.id = $id AND NOT 'Decision' IN labels(x) AND NOT 'Finding' IN labels(x) " +
                "RETURN x.id AS id, x.name AS name, labels(x)[0] AS label, " +
                "       x.sensitive AS sensitive, " +
                "       [n IN nodes(p) | n.name] AS via, " +
                "       length(p) AS hops",
                Map.of("id", res.id()));
        Map<String, Map<String, Object>> shortest = new LinkedHashMap<>();
        for (Map<String, Object> r : rawRows) {
            String id = String.valueOf(r.get("id"));
            int hops = ((Number) r.get("hops")).intValue();
            if (!shortest.containsKey(id) || hops < ((Number) shortest.get(id).get("hops")).intValue()) {
                shortest.put(id, r);
            }
        }
        List<Map<String, Object>> uniqueNodes = new ArrayList<>(shortest.values());
        uniqueNodes.sort(Comparator.comparingInt((Map<String, Object> m) -> ((Number) m.get("hops")).intValue())
                .thenComparing(m -> String.valueOf(m.get("name"))));

        Map<String, Integer> byLabel = new TreeMap<>();
        List<String> sensitiveReached = new ArrayList<>();
        List<Map<String, Object>> sensitive = new ArrayList<>();
        for (Map<String, Object> r : uniqueNodes) {
            String lbl = String.valueOf(r.get("label"));
            byLabel.merge(lbl, 1, Integer::sum);
            if (Boolean.TRUE.equals(r.get("sensitive"))) {
                String sName = String.valueOf(r.get("name"));
                if (!sensitiveReached.contains(sName)) {
                    sensitiveReached.add(sName);
                }
                Map<String, Object> sDetail = new LinkedHashMap<>();
                sDetail.put("name", sName);
                sDetail.put("hops", r.get("hops"));
                sDetail.put("route", r.get("via"));
                sensitive.add(sDetail);
            }
        }

        Map<String, Integer> byDepth = new LinkedHashMap<>();
        for (int d = 1; d <= cap; d++) {
            final int currD = d;
            int count = (int) uniqueNodes.stream().filter(n -> ((Number) n.get("hops")).intValue() <= currD).count();
            byDepth.put(String.valueOf(d), count);
        }

        String outcome = uniqueNodes.isEmpty() ? "not_in_graph" : "answered_with_path";

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("outcome", outcome);
        out.put("query", text);
        out.put("resolvedId", res.id());
        out.put("resolvedName", res.name());
        out.put("depth", cap);
        out.put("reachableCount", uniqueNodes.size());
        out.put("rows", uniqueNodes.size());
        out.put("byLabel", byLabel);
        out.put("sensitiveReached", sensitiveReached);
        out.put("sensitive", sensitive);
        out.put("byDepth", byDepth);
        out.put("nodes", uniqueNodes);
        out.put("millis", System.currentTimeMillis() - t0);
        return out;
    }

    public Map<String, Object> pathBetween(String graph, String from, String to) {
        long t0 = System.currentTimeMillis();
        ResolvedNode resFrom = resolve(graph, from);
        ResolvedNode resTo = resolve(graph, to);
        if (!resFrom.found() || !resTo.found()) {
            String missing = !resFrom.found() ? (!resTo.found() ? from + ", " + to : from) : to;
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("outcome", "unknown_node");
            out.put("from", from);
            out.put("to", to);
            out.put("rows", 0);
            out.put("message", "Unknown node(s): " + missing);
            out.put("millis", System.currentTimeMillis() - t0);
            return out;
        }

        List<Map<String, Object>> rows = List.of();
        try {
            rows = graphs.read(graph,
                    "MATCH (a {id:$from}), (b {id:$to}) " +
                    "CALL algo.SPpaths(a, b, '" + EDGE_TYPES_JOINED + "') YIELD path " +
                    "RETURN [n IN nodes(path) | n.id] AS ids, " +
                    "       [n IN nodes(path) | n.name] AS names, " +
                    "       [n IN nodes(path) | labels(n)[0]] AS labels, " +
                    "       [r IN relationships(path) | type(r)] AS types, " +
                    "       length(path) AS hops LIMIT 1",
                    Map.of("from", resFrom.id(), "to", resTo.id()));
        } catch (Exception e) {
            try {
                rows = graphs.read(graph,
                        "MATCH (a {id:$from}), (b {id:$to}) " +
                        "MATCH p = shortestPath((a)-[:" + EDGE_TYPES_JOINED + "*1..10]->(b)) " +
                        "RETURN [n IN nodes(p) | n.id] AS ids, " +
                        "       [n IN nodes(p) | n.name] AS names, " +
                        "       [n IN nodes(p) | labels(n)[0]] AS labels, " +
                        "       [r IN relationships(p) | type(r)] AS types, " +
                        "       length(p) AS hops LIMIT 1",
                        Map.of("from", resFrom.id(), "to", resTo.id()));
            } catch (Exception ignored) {
            }
        }

        if (rows.isEmpty()) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("outcome", "not_in_graph");
            out.put("from", resFrom.name());
            out.put("to", resTo.name());
            out.put("rows", 0);
            out.put("message", "No path found between " + resFrom.name() + " and " + resTo.name());
            out.put("millis", System.currentTimeMillis() - t0);
            return out;
        }

        Map<String, Object> r = rows.get(0);
        List<String> ids = strings(r.get("ids"));
        List<String> names = strings(r.get("names"));
        List<String> labels = strings(r.get("labels"));
        List<String> types = strings(r.get("types"));
        int hops = ((Number) r.get("hops")).intValue();
        List<String> sentences = new ArrayList<>();
        for (int i = 0; i < types.size(); i++) {
            sentences.add(sentence(types.get(i), names.get(i), names.get(i + 1)));
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("outcome", "answered_with_path");
        out.put("from", resFrom.name());
        out.put("to", resTo.name());
        out.put("hops", hops);
        out.put("nodeIds", ids);
        out.put("nodeNames", names);
        out.put("nodeLabels", labels);
        out.put("edgeTypes", types);
        out.put("sentences", sentences);
        out.put("rows", 1);
        out.put("millis", System.currentTimeMillis() - t0);
        return out;
    }

    public Map<String, Object> loadBearing(String graph, int limit) {
        long t0 = System.currentTimeMillis();
        int cap = Math.max(1, limit);
        String algo = "algo.pageRank";
        List<Map<String, Object>> rows = List.of();
        try {
            rows = graphs.read(graph,
                    "CALL algo.pageRank(null, null) YIELD node, score " +
                    "WHERE NOT 'Decision' IN labels(node) AND NOT 'Finding' IN labels(node) " +
                    "RETURN node.id AS id, node.name AS name, labels(node)[0] AS label, score " +
                    "ORDER BY score DESC LIMIT " + cap,
                    Map.of());
        } catch (Exception e) {
            algo = "in-degree fallback (pageRank unavailable)";
            rows = graphs.read(graph,
                    "MATCH (n) WHERE NOT 'Decision' IN labels(n) AND NOT 'Finding' IN labels(n) " +
                    "OPTIONAL MATCH ()-[r]->(n) WHERE NOT 'Decision' IN labels(startNode(r)) AND NOT 'Finding' IN labels(startNode(r)) " +
                    "RETURN n.id AS id, n.name AS name, labels(n)[0] AS label, count(r) AS inDegree, count(r) AS score " +
                    "ORDER BY score DESC, name ASC LIMIT " + cap,
                    Map.of());
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("algorithm", algo);
        out.put("limit", cap);
        out.put("rows", rows);
        out.put("outcome", rows.isEmpty() ? "not_in_graph" : "answered_with_path");
        out.put("millis", System.currentTimeMillis() - t0);
        return out;
    }

    public Map<String, Object> recall(String graph, String nodeText) {
        long t0 = System.currentTimeMillis();
        ResolvedNode res = resolve(graph, nodeText);
        if (!res.found()) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("outcome", "unknown_node");
            out.put("node", nodeText);
            out.put("rows", 0);
            out.put("records", List.of());
            out.put("message", res.message());
            out.put("millis", System.currentTimeMillis() - t0);
            return out;
        }
        List<Map<String, Object>> decisions = graphs.read(graph,
                "MATCH (d:Decision)-[:APPLIES_TO]->(n) WHERE n.id = $id " +
                "RETURN d.id AS id, d.name AS name, d.owner AS owner, d.reason AS reason, " +
                "       d.expiresAt AS expiresAt, d.at AS at, 'Decision' AS type, n.name AS nodeName",
                Map.of("id", res.id()));
        List<Map<String, Object>> findings = graphs.read(graph,
                "MATCH (f:Finding)-[:ABOUT]->(n) WHERE n.id = $id " +
                "RETURN f.id AS id, f.text AS text, f.at AS at, 'Finding' AS type, n.name AS nodeName",
                Map.of("id", res.id()));
        List<Map<String, Object>> combined = new ArrayList<>();
        combined.addAll(decisions);
        combined.addAll(findings);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("outcome", "memory");
        out.put("node", res.name());
        out.put("nodeId", res.id());
        out.put("records", combined);
        out.put("rows", combined.size());
        out.put("millis", System.currentTimeMillis() - t0);
        return out;
    }

    public Map<String, Object> saveFinding(String graph, String nodeText, String text) {
        long t0 = System.currentTimeMillis();
        ResolvedNode res = resolve(graph, nodeText);
        if (!res.found()) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("outcome", "unknown_node");
            out.put("node", nodeText);
            out.put("rows", 0);
            out.put("message", res.message());
            out.put("millis", System.currentTimeMillis() - t0);
            return out;
        }
        String id = "find:" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String at = Instant.now().toString();
        List<String> targets = List.of(res.id());
        graphs.write(graph,
                "MERGE (f:Finding {id:$id}) SET f.text = $text, f.at = $at, f.targets = $targets",
                Map.of("id", id, "text", text, "at", at, "targets", targets));
        graphs.write(graph,
                "MATCH (f:Finding {id:$id}), (n {id:$nid}) MERGE (f)-[:ABOUT]->(n)",
                Map.of("id", id, "nid", res.id()));

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("outcome", "memory");
        out.put("id", id);
        out.put("node", res.name());
        out.put("text", text);
        out.put("at", at);
        out.put("rows", 1);
        out.put("millis", System.currentTimeMillis() - t0);
        return out;
    }

    public Map<String, Object> chokePoints(String graph) {
        List<AttackPath> all = findPaths(graph);
        List<AttackPath> active = all.stream().filter(p -> !p.accepted()).toList();
        Map<String, Integer> nodeCount = new HashMap<>();
        Map<String, String[]> nodeInfo = new HashMap<>();
        Map<String, Integer> edgeCount = new HashMap<>();
        Map<String, Edge> edgeRef = new HashMap<>();
        Map<String, String> edgeDesc = new HashMap<>();
        for (AttackPath p : active) {
            for (int i = 0; i < p.nodeIds().size(); i++) {
                nodeCount.merge(p.nodeIds().get(i), 1, Integer::sum);
                nodeInfo.putIfAbsent(p.nodeIds().get(i), new String[]{p.nodeNames().get(i), p.nodeLabels().get(i)});
            }
            for (int i = 0; i < p.edgeTypes().size(); i++) {
                String k = p.nodeIds().get(i) + "|" + p.edgeTypes().get(i) + "|" + p.nodeIds().get(i + 1);
                edgeCount.merge(k, 1, Integer::sum);
                edgeRef.putIfAbsent(k, new Edge(p.nodeIds().get(i), p.edgeTypes().get(i), p.nodeIds().get(i + 1)));
                edgeDesc.putIfAbsent(k, p.nodeNames().get(i) + " -[" + p.edgeTypes().get(i) + "]-> " + p.nodeNames().get(i + 1));
            }
        }
        List<RankedEdge> edges = edgeCount.entrySet().stream()
                .map(e -> new RankedEdge(edgeRef.get(e.getKey()).source(), edgeRef.get(e.getKey()).type(), edgeRef.get(e.getKey()).target(),
                        edgeDesc.get(e.getKey()), e.getValue()))
                .sorted(Comparator.comparingInt(RankedEdge::paths).reversed().thenComparing(RankedEdge::description))
                .limit(6).toList();
        List<RankedNode> nodes = nodeCount.entrySet().stream()
                .map(e -> new RankedNode(e.getKey(), nodeInfo.get(e.getKey())[0], nodeInfo.get(e.getKey())[1], e.getValue()))
                .sorted(Comparator.comparingInt(RankedNode::paths).reversed().thenComparing(RankedNode::name))
                .limit(6).toList();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("totalPaths", all.size());
        out.put("activePaths", active.size());
        out.put("edges", edges);
        out.put("nodes", nodes);
        out.put("outcome", active.isEmpty() ? "not_in_graph" : "answered_with_path");
        out.put("rows", edges.size());
        return out;
    }

    public SimResult simulate(Edge e) {
        if (!EDGE_TYPES.contains(e.type())) {
            throw new IllegalArgumentException("Unknown edge type: " + e.type());
        }
        long t0 = System.nanoTime();
        Set<String> before = findPaths(graphs.main()).stream().map(AttackPath::key).collect(Collectors.toCollection(LinkedHashSet::new));
        Map<String, Object> p = Map.of("s", e.source(), "t", e.target());
        List<Map<String, Object>> check = graphs.read(graphs.main(),
                "MATCH (a {id:$s})-[r:" + e.type() + "]->(b {id:$t}) RETURN count(r) AS c", p);
        boolean existed = !check.isEmpty() && check.get(0).get("c") instanceof Number n && n.longValue() > 0;
        if (!existed) {
            return new SimResult(e, before.size(), before.size(), List.of(), List.of(), false, proposal(e.type()), (System.nanoTime() - t0) / 1_000_000);
        }
        String sim = "sim_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        Set<String> after;
        try {
            ingestor.buildSim(sim);
            graphs.write(sim, "MATCH (a {id:$s})-[r:" + e.type() + "]->(b {id:$t}) DELETE r", p);
            after = findPaths(sim).stream().map(AttackPath::key).collect(Collectors.toCollection(LinkedHashSet::new));
        } finally {
            graphs.deleteGraph(sim);
        }
        List<String> removed = before.stream().filter(k -> !after.contains(k)).toList();
        List<String> added = after.stream().filter(k -> !before.contains(k)).toList();
        return new SimResult(e, before.size(), after.size(), removed, added, true, proposal(e.type()), (System.nanoTime() - t0) / 1_000_000);
    }

    public void acceptRisk(String graph, String pathKey, String owner, String reason, int days) {
        AttackPath path = findPaths(graph).stream().filter(p -> p.key().equals(pathKey)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown path key"));
        long now = System.currentTimeMillis();
        long expires = now + days * 86_400_000L;
        String at = Instant.now().toString();
        graphs.write(graph, "MERGE (d:Decision {id:$id}) SET d.name = $name, d.owner = $owner, d.reason = $reason, d.expiresAt = $exp, d.at = $at, d.targets = $targets",
                Map.of("id", pathKey, "name", "accepted risk " + pathKey, "owner", owner, "reason", reason, "exp", expires, "at", at, "targets", path.nodeIds()));
        for (String nodeId : path.nodeIds()) {
            graphs.write(graph, "MATCH (d:Decision {id:$d}), (n {id:$n}) MERGE (d)-[:APPLIES_TO]->(n)", Map.of("d", pathKey, "n", nodeId));
        }
    }

    private Map<String, String> activeDecisions(String graph) {
        Map<String, String> out = new HashMap<>();
        long now = System.currentTimeMillis();
        for (Map<String, Object> row : graphs.read(graph, "MATCH (d:Decision) RETURN d.id AS id, d.owner AS owner, d.expiresAt AS exp", Map.of())) {
            if (row.get("exp") instanceof Number n && n.longValue() > now) {
                out.put(String.valueOf(row.get("id")), String.valueOf(row.get("owner")));
            }
        }
        return out;
    }

    private static List<String> strings(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof List<?> l) {
            for (Object x : l) {
                out.add(x == null ? "" : String.valueOf(x));
            }
        }
        return out;
    }

    static String key(List<String> ids, List<String> types) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest((String.join(">", ids) + "|" + String.join(",", types)).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(d).substring(0, 12);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String sentence(String type, String a, String b) {
        return switch (type) {
            case "FIRES" -> "Event '" + a + "' starts workflow '" + b + "', which runs attacker-controlled input";
            case "RUNS_JOB" -> "Workflow '" + a + "' runs job '" + b + "'";
            case "CAN_READ" -> "Job '" + a + "' can read secret " + b;
            case "ASSUMES" -> "Job '" + a + "' assumes cloud role '" + b + "' (CI/CD to IAM bridge)";
            case "CAN_ASSUME" -> "Role '" + a + "' can assume role '" + b + "'";
            case "CAN_PASS_ROLE" -> "Role '" + a + "' can create a service and pass role '" + b + "' to it";
            case "CAN_UPDATE_CODE" -> "Role '" + a + "' can overwrite the code of '" + b + "'";
            case "EXECUTES_AS" -> "'" + a + "' runs with the permissions of role '" + b + "'";
            case "CAN_ACCESS" -> "Role '" + a + "' has access to '" + b + "'";
            case "RUNS_IN" -> "Action '" + a + "' executes inside job '" + b + "'";
            default -> a + " -> " + b;
        };
    }

    private static String proposal(String type) {
        return switch (type) {
            case "FIRES" -> "Do not run untrusted code in a privileged workflow: trigger on pull_request instead of pull_request_target, or remove the checkout of the PR head, and never interpolate github.event values into run steps.";
            case "ASSUMES" -> "Use a dedicated least-privilege role for this job and restrict the role's trust policy to the main branch via the OIDC sub claim.";
            case "CAN_PASS_ROLE" -> "Remove iam:PassRole for this target role, or restrict it to a specific non-admin role, and remove compute-creation permissions (lambda:CreateFunction, ec2:RunInstances) from the source role.";
            case "CAN_UPDATE_CODE" -> "Remove lambda:UpdateFunctionCode for this function from the role, or give the function its own least-privilege execution role.";
            case "EXECUTES_AS" -> "Give the function a dedicated least-privilege execution role instead of the privileged one.";
            case "CAN_ACCESS" -> "Replace broad actions with the exact actions needed and restrict the resource.";
            case "CAN_READ" -> "Pass the secret only to the step that needs it, and use environment protection so untrusted runs cannot read it.";
            default -> "Remove or restrict this relationship.";
        };
    }
}