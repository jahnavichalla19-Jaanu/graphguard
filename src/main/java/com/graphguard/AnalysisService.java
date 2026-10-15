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

    public List<AttackPath> findPaths(String graph) {
        Map<String, String> accepted = activeDecisions(graph);
        Map<String, AttackPath> unique = new LinkedHashMap<>();
        for (Map<String, Object> row : graphs.query(graph, PATH_QUERY, Map.of())) {
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
        List<Map<String, Object>> nodes = graphs.query(graph, """
                MATCH (n) WHERE NOT 'Decision' IN labels(n)
                RETURN n.id AS id, n.name AS name, labels(n)[0] AS label, n.sensitive AS sensitive, n.untrusted AS untrusted, n.pinned AS pinned
                """, Map.of());
        List<Map<String, Object>> edges = graphs.query(graph, """
                MATCH (a)-[r]->(b) WHERE NOT 'Decision' IN labels(a)
                RETURN a.id AS source, b.id AS target, type(r) AS type
                """, Map.of());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("nodes", nodes);
        out.put("edges", edges);
        return out;
    }

    public Map<String, Object> blastRadius(String graph, String query) {
        List<Map<String, Object>> rows = graphs.query(graph, """
                MATCH p = (s)-[*1..6]->(x)
                WHERE (s.id = $q OR toLower(s.name) CONTAINS toLower($q))
                  AND NOT 'Decision' IN labels(s) AND NOT 'Decision' IN labels(x)
                RETURN DISTINCT x.id AS id, x.name AS name, labels(x)[0] AS label, x.sensitive AS sensitive
                """, Map.of("q", query));
        Map<String, Integer> byLabel = new TreeMap<>();
        List<String> sensitive = new ArrayList<>();
        for (Map<String, Object> r : rows) {
            byLabel.merge(String.valueOf(r.get("label")), 1, Integer::sum);
            if (Boolean.TRUE.equals(r.get("sensitive"))) {
                sensitive.add(String.valueOf(r.get("name")));
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("query", query);
        out.put("reachableCount", rows.size());
        out.put("byLabel", byLabel);
        out.put("sensitiveReached", sensitive);
        out.put("nodes", rows);
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
        return out;
    }

    public SimResult simulate(Edge e) {
        if (!EDGE_TYPES.contains(e.type())) {
            throw new IllegalArgumentException("Unknown edge type: " + e.type());
        }
        long t0 = System.nanoTime();
        Set<String> before = findPaths(graphs.main()).stream().map(AttackPath::key).collect(Collectors.toCollection(LinkedHashSet::new));
        String sim = "sim_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        Set<String> after;
        boolean existed;
        try {
            ingestor.buildSim(sim);
            Map<String, Object> p = Map.of("s", e.source(), "t", e.target());
            Object c = graphs.query(sim, "MATCH (a {id:$s})-[r:" + e.type() + "]->(b {id:$t}) RETURN count(r) AS c", p).get(0).get("c");
            existed = c instanceof Number n && n.longValue() > 0;
            if (existed) {
                graphs.write(sim, "MATCH (a {id:$s})-[r:" + e.type() + "]->(b {id:$t}) DELETE r", p);
            }
            after = findPaths(sim).stream().map(AttackPath::key).collect(Collectors.toCollection(LinkedHashSet::new));
        } finally {
            graphs.deleteGraph(sim);
        }
        List<String> removed = before.stream().filter(k -> !after.contains(k)).toList();
        List<String> added = after.stream().filter(k -> !before.contains(k)).toList();
        return new SimResult(e, before.size(), after.size(), removed, added, existed, proposal(e.type()), (System.nanoTime() - t0) / 1_000_000);
    }

    public void acceptRisk(String graph, String pathKey, String owner, String reason, int days) {
        AttackPath path = findPaths(graph).stream().filter(p -> p.key().equals(pathKey)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown path key"));
        long expires = System.currentTimeMillis() + days * 86_400_000L;
        graphs.write(graph, "MERGE (d:Decision {id:$id}) SET d.name = $name, d.owner = $owner, d.reason = $reason, d.expiresAt = $exp",
                Map.of("id", pathKey, "name", "accepted risk " + pathKey, "owner", owner, "reason", reason, "exp", expires));
        for (String nodeId : path.nodeIds()) {
            graphs.write(graph, "MATCH (d:Decision {id:$d}), (n {id:$n}) MERGE (d)-[:APPLIES_TO]->(n)", Map.of("d", pathKey, "n", nodeId));
        }
    }

    private Map<String, String> activeDecisions(String graph) {
        Map<String, String> out = new HashMap<>();
        long now = System.currentTimeMillis();
        for (Map<String, Object> row : graphs.query(graph, "MATCH (d:Decision) RETURN d.id AS id, d.owner AS owner, d.expiresAt AS exp", Map.of())) {
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