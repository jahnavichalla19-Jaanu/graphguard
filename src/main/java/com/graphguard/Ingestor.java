package com.graphguard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.graphguard.Models.SourceSet;
import com.graphguard.Models.WorkflowFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class Ingestor {
    private static final Logger log = LoggerFactory.getLogger(Ingestor.class);
    private static final Set<String> UNTRUSTED_EVENTS = Set.of("pull_request_target", "issue_comment", "workflow_run");
    private static final Pattern SHA = Pattern.compile("^[0-9a-f]{40}$");
    private static final Pattern SECRET = Pattern.compile("\\$\\{\\{\\s*secrets\\.([A-Za-z0-9_]+)\\s*\\}\\}");
    private static final Pattern SAFE_NAME = Pattern.compile("^[A-Za-z0-9_.-]+$");
    private static final List<String> LABELS = List.of("Repo", "Workflow", "Trigger", "Job", "Action", "Secret", "Role", "Resource", "Decision");
    private static final List<String> COMPUTE_ACTIONS = List.of("lambda:CreateFunction", "ec2:RunInstances", "cloudformation:CreateStack", "glue:CreateDevEndpoint");

    private final GraphService graphs;
    private final String githubToken;
    private final ObjectMapper json = new ObjectMapper();
    private final ObjectMapper yaml = new ObjectMapper(new YAMLFactory());
    private final RestClient http = RestClient.create();
    private volatile SourceSet lastSources;

    public Ingestor(GraphService graphs, @Value("${github.token:}") String githubToken) {
        this.graphs = graphs;
        this.githubToken = githubToken;
    }

    public SourceSet lastSources() {
        return lastSources;
    }

    public SourceSet sampleSources() {
        try {
            List<WorkflowFile> files = new ArrayList<>();
            for (Resource r : new PathMatchingResourcePatternResolver().getResources("classpath:sample/workflows/*.yml")) {
                files.add(new WorkflowFile("demo-org/shop-web", ".github/workflows/" + r.getFilename(), r.getContentAsString(StandardCharsets.UTF_8)));
            }
            files.sort(Comparator.comparing(WorkflowFile::path));
            String iam = new ClassPathResource("sample/iam-policies.json").getContentAsString(StandardCharsets.UTF_8);
            return new SourceSet(files, iam);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read sample data", e);
        }
    }

    public SourceSet githubSources(String owner, String repo) {
        if (!SAFE_NAME.matcher(owner).matches() || !SAFE_NAME.matcher(repo).matches()) {
            throw new IllegalArgumentException("Invalid owner or repo name");
        }
        List<WorkflowFile> files = new ArrayList<>();
        try {
            JsonNode listing = json.readTree(get("https://api.github.com/repos/" + owner + "/" + repo + "/contents/.github/workflows", String.class));
            for (JsonNode f : listing) {
                String name = f.path("name").asText();
                String url = f.path("download_url").asText("");
                if ((name.endsWith(".yml") || name.endsWith(".yaml")) && url.startsWith("https://raw.githubusercontent.com/")) {
                    files.add(new WorkflowFile(owner + "/" + repo, ".github/workflows/" + name, get(url, String.class)));
                }
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Could not read .github/workflows of " + owner + "/" + repo
                    + " (private repo, no workflows, or rate limit). Set GITHUB_TOKEN to raise the limit.");
        }
        if (files.isEmpty()) {
            throw new IllegalArgumentException("No workflow files found in " + owner + "/" + repo);
        }
        return new SourceSet(files, sampleSources().iamJson());
    }

    public synchronized void loadMain(SourceSet src) {
        lastSources = src;
        ingest(graphs.main(), src, true);
    }

    public void buildSim(String simGraph) {
        if (lastSources == null) {
            throw new IllegalStateException("Load data first");
        }
        ingest(simGraph, lastSources, false);
    }

    private void ingest(String graph, SourceSet src, boolean reset) {
        if (reset) {
            graphs.write(graph, "MATCH (n) WHERE NOT 'Decision' IN labels(n) DETACH DELETE n", Map.of());
        }
        for (String label : LABELS) {
            try {
                graphs.write(graph, "CREATE INDEX FOR (n:" + label + ") ON (n.id)", Map.of());
            } catch (Exception ignored) {
            }
        }
        ingestIam(graph, src.iamJson());
        for (WorkflowFile wf : src.workflows()) {
            ingestWorkflow(graph, wf);
        }
    }

    private void ingestIam(String g, String iamJson) {
        JsonNode root;
        try {
            root = json.readTree(iamJson);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid IAM JSON: " + e.getMessage());
        }
        List<String> roles = new ArrayList<>();
        Map<String, String> resourceType = new LinkedHashMap<>();
        for (JsonNode r : root.path("roles")) {
            String name = r.path("name").asText();
            roles.add(name);
            node(g, "Role", "role:" + name, Map.of("name", name, "isAdmin", r.path("admin").asBoolean(false)));
        }
        for (JsonNode r : root.path("resources")) {
            String name = r.path("name").asText();
            String type = r.path("type").asText("unknown");
            resourceType.put(name, type);
            node(g, "Resource", "resource:" + name, Map.of("name", name, "type", type, "sensitive", r.path("sensitive").asBoolean(false)));
        }
        for (JsonNode r : root.path("resources")) {
            String exec = r.path("executesAs").asText("");
            if (!exec.isEmpty()) {
                edge(g, "Resource", "resource:" + r.path("name").asText(), "EXECUTES_AS", "Role", "role:" + exec);
            }
        }
        for (JsonNode r : root.path("roles")) {
            String from = "role:" + r.path("name").asText();
            List<String[]> grants = new ArrayList<>();
            for (JsonNode stmt : r.path("allow")) {
                if (stmt.has("condition")) {
                    log.warn("Condition on {} ignored (unsupported)", from);
                }
                for (JsonNode a : stmt.path("actions")) {
                    for (JsonNode t : stmt.path("resources")) {
                        grants.add(new String[]{a.asText(), t.asText()});
                    }
                }
            }
            boolean canCreateCompute = grants.stream().anyMatch(gr -> COMPUTE_ACTIONS.stream().anyMatch(c -> glob(gr[0], c)));
            Map<String, Set<String>> access = new LinkedHashMap<>();
            for (String[] gr : grants) {
                String action = gr[0];
                for (String roleName : roles) {
                    String to = "role:" + roleName;
                    if (to.equals(from) || !glob(gr[1], roleName)) {
                        continue;
                    }
                    if (glob(action, "sts:AssumeRole")) {
                        edge(g, "Role", from, "CAN_ASSUME", "Role", to);
                    }
                    if (canCreateCompute && glob(action, "iam:PassRole")) {
                        edge(g, "Role", from, "CAN_PASS_ROLE", "Role", to);
                    }
                }
                for (Map.Entry<String, String> res : resourceType.entrySet()) {
                    if (!glob(gr[1], res.getKey())) {
                        continue;
                    }
                    String to = "resource:" + res.getKey();
                    String lower = action.toLowerCase();
                    if (res.getValue().equals("lambda") && glob(action, "lambda:UpdateFunctionCode")) {
                        edge(g, "Role", from, "CAN_UPDATE_CODE", "Resource", to);
                    } else if (!lower.startsWith("iam:") && !lower.startsWith("sts:")
                            && COMPUTE_ACTIONS.stream().noneMatch(c -> c.equalsIgnoreCase(action))
                            && serviceMatches(action, res.getValue())) {
                        access.computeIfAbsent(to, k -> new TreeSet<>()).add(action);
                    }
                }
            }
            access.forEach((to, acts) -> edge(g, "Role", from, "CAN_ACCESS", "Resource", to, Map.of("actions", String.join(",", acts))));
        }
    }

    private void ingestWorkflow(String g, WorkflowFile wf) {
        JsonNode doc;
        try {
            doc = yaml.readTree(wf.yaml());
        } catch (IOException e) {
            log.warn("Skipping unreadable workflow {}", wf.path());
            return;
        }
        String repoId = "repo:" + wf.repo();
        String wfId = "wf:" + wf.repo() + ":" + wf.path();
        JsonNode on = doc.has("on") ? doc.get("on") : doc.path("true");
        Set<String> events = new LinkedHashSet<>();
        if (on.isTextual()) {
            events.add(on.asText());
        } else if (on.isArray()) {
            on.forEach(x -> events.add(x.asText()));
        } else if (on.isObject()) {
            on.fieldNames().forEachRemaining(events::add);
        }
        JsonNode jobs = doc.path("jobs");
        boolean exploitable = runsUntrustedCode(jobs);
        node(g, "Repo", repoId, Map.of("name", wf.repo()));
        node(g, "Workflow", wfId, Map.of("name", wf.path().substring(wf.path().lastIndexOf('/') + 1), "path", wf.path(), "executesUntrusted", exploitable));
        edge(g, "Repo", repoId, "HAS_WORKFLOW", "Workflow", wfId);
        for (String event : events) {
            String trg = "trg:" + wfId + ":" + event;
            boolean untrusted = UNTRUSTED_EVENTS.contains(event);
            node(g, "Trigger", trg, Map.of("name", event, "untrusted", untrusted));
            if (!untrusted || exploitable) {
                edge(g, "Trigger", trg, "FIRES", "Workflow", wfId);
            }
        }
        Iterator<Map.Entry<String, JsonNode>> it = jobs.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> entry = it.next();
            String jobName = entry.getKey();
            JsonNode job = entry.getValue();
            String jobId = "job:" + wfId + ":" + jobName;
            JsonNode perms = job.has("permissions") ? job.get("permissions") : doc.path("permissions");
            String permText = perms.isMissingNode() || perms.isNull() ? "default" : perms.isTextual() ? perms.asText() : perms.toString();
            node(g, "Job", jobId, Map.of("name", jobName, "permissions", permText));
            edge(g, "Workflow", wfId, "RUNS_JOB", "Job", jobId);
            for (JsonNode step : job.path("steps")) {
                String uses = step.path("uses").asText("");
                if (uses.isEmpty() || uses.startsWith("./") || uses.startsWith("docker://")) {
                    continue;
                }
                int at = uses.lastIndexOf('@');
                String actionName = at > 0 ? uses.substring(0, at) : uses;
                String ref = at > 0 ? uses.substring(at + 1) : "none";
                String actId = "act:" + uses;
                boolean third = !(actionName.startsWith("actions/") || actionName.startsWith("github/"));
                node(g, "Action", actId, Map.of("name", uses, "pinned", SHA.matcher(ref).matches(), "thirdParty", third));
                edge(g, "Action", actId, "RUNS_IN", "Job", jobId);
                if (actionName.equals("aws-actions/configure-aws-credentials")) {
                    String arn = step.path("with").path("role-to-assume").asText("");
                    int idx = arn.lastIndexOf("role/");
                    if (idx >= 0) {
                        String roleName = arn.substring(arn.lastIndexOf('/') + 1);
                        node(g, "Role", "role:" + roleName, Map.of("name", roleName));
                        edge(g, "Job", jobId, "ASSUMES", "Role", "role:" + roleName);
                    }
                }
            }
            Matcher m = SECRET.matcher(job.toString());
            Set<String> secrets = new LinkedHashSet<>();
            while (m.find()) {
                secrets.add(m.group(1));
            }
            for (String s : secrets) {
                String secId = "secret:" + wf.repo() + ":" + s;
                node(g, "Secret", secId, Map.of("name", s, "sensitive", true));
                edge(g, "Job", jobId, "CAN_READ", "Secret", secId);
            }
        }
    }

    private boolean runsUntrustedCode(JsonNode jobs) {
        Iterator<JsonNode> it = jobs.elements();
        while (it.hasNext()) {
            for (JsonNode step : it.next().path("steps")) {
                String uses = step.path("uses").asText("");
                String ref = step.path("with").path("ref").asText("");
                String run = step.path("run").asText("");
                if (uses.startsWith("actions/checkout") && (ref.contains("github.event.pull_request.head") || ref.contains("github.head_ref"))) {
                    return true;
                }
                if (run.contains("${{ github.event.") || run.contains("${{ github.head_ref")) {
                    return true;
                }
            }
        }
        return false;
    }

    private void node(String g, String label, String id, Map<String, Object> props) {
        Map<String, Object> params = new LinkedHashMap<>(props);
        params.put("id", id);
        String set = props.keySet().stream().map(k -> "n." + k + " = $" + k).collect(Collectors.joining(", "));
        graphs.write(g, "MERGE (n:" + label + " {id:$id}) SET " + set, params);
    }

    private void edge(String g, String aLabel, String a, String type, String bLabel, String b) {
        edge(g, aLabel, a, type, bLabel, b, Map.of());
    }

    private void edge(String g, String aLabel, String a, String type, String bLabel, String b, Map<String, Object> props) {
        Map<String, Object> params = new LinkedHashMap<>(props);
        params.put("a", a);
        params.put("b", b);
        StringBuilder q = new StringBuilder("MATCH (x:").append(aLabel).append(" {id:$a}), (y:").append(bLabel)
                .append(" {id:$b}) MERGE (x)-[r:").append(type).append("]->(y)");
        if (!props.isEmpty()) {
            q.append(" SET ").append(props.keySet().stream().map(k -> "r." + k + " = $" + k).collect(Collectors.joining(", ")));
        }
        graphs.write(g, q.toString(), params);
    }

    private static boolean serviceMatches(String action, String type) {
        String svc = action.contains(":") ? action.substring(0, action.indexOf(':')) : action;
        return svc.equals("*") || glob(svc, type);
    }

    static boolean glob(String pattern, String text) {
        String regex = Arrays.stream(pattern.split("\\*", -1)).map(Pattern::quote).collect(Collectors.joining(".*"));
        return Pattern.compile("^" + regex + "$", Pattern.CASE_INSENSITIVE).matcher(text).matches();
    }

    private <T> T get(String url, Class<T> type) {
        return http.get().uri(URI.create(url))
                .header("Accept", "application/vnd.github+json")
                .headers(h -> {
                    if (!githubToken.isBlank()) {
                        h.setBearerAuth(githubToken);
                    }
                })
                .retrieve().body(type);
    }
}