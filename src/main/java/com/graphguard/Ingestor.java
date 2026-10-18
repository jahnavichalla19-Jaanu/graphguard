package com.graphguard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.graphguard.AwsIamService.IamParseResult;
import com.graphguard.AwsIamService.ParsedResource;
import com.graphguard.AwsIamService.ParsedRole;
import com.graphguard.AwsIamService.PolicyStatement;
import com.graphguard.Models.SourceSet;
import com.graphguard.Models.WorkflowFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class Ingestor implements InitializingBean {
    private static final Logger log = LoggerFactory.getLogger(Ingestor.class);
    private static final Set<String> UNTRUSTED_EVENTS = Set.of("pull_request_target", "issue_comment", "workflow_run");
    private static final Pattern SHA = Pattern.compile("^[0-9a-f]{40}$");
    private static final Pattern SECRET = Pattern.compile("\\$\\{\\{\\s*secrets\\.([A-Za-z0-9_]+)\\s*\\}\\}");
    private static final Pattern SAFE_NAME = Pattern.compile("^[A-Za-z0-9_.-]+$");
    private static final List<String> LABELS = List.of("Repo", "Workflow", "Trigger", "Job", "Action", "Secret", "Role", "Resource", "Decision", "Finding");
    private static final List<String> COMPUTE_ACTIONS = List.of("lambda:CreateFunction", "ec2:RunInstances", "cloudformation:CreateStack", "glue:CreateDevEndpoint");

    private final GraphService graphs;
    private final AwsIamService awsIamService;
    private final String githubToken;
    private final ObjectMapper json = new ObjectMapper();
    private final ObjectMapper yaml = new ObjectMapper(new YAMLFactory());
    private final RestClient http;
    private volatile SourceSet lastSources;
    private volatile String userUploadedIam = null;
    private volatile String iamStatus = "none";

    public String iamStatus() {
        return iamStatus;
    }

    public void resetUserUploadedIam() {
        this.userUploadedIam = null;
        this.iamStatus = "none";
    }

    private final List<String> lastWarnings = new ArrayList<>();
    private int lastPrunedPaths = 0;
    private final Set<String> indexedGraphs = ConcurrentHashMap.newKeySet();
    private final List<Runnable> invalidationListeners = new CopyOnWriteArrayList<>();

    private static RestClient createDefaultRestClient() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(5));
        factory.setReadTimeout(Duration.ofSeconds(20));
        return RestClient.builder().requestFactory(factory).build();
    }

    public Ingestor(GraphService graphs, @Value("${github.token:}") String githubToken) {
        this(graphs, new AwsIamService(), githubToken);
    }

    @Autowired
    public Ingestor(GraphService graphs, AwsIamService awsIamService, @Value("${github.token:}") String githubToken) {
        this(graphs, awsIamService, githubToken, createDefaultRestClient());
    }

    Ingestor(GraphService graphs, AwsIamService awsIamService, String githubToken, RestClient http) {
        this.graphs = graphs;
        this.awsIamService = awsIamService != null ? awsIamService : new AwsIamService();
        this.githubToken = githubToken != null ? githubToken : "";
        this.http = http != null ? http : createDefaultRestClient();
    }

    public void addInvalidationListener(Runnable listener) {
        if (listener != null) {
            invalidationListeners.add(listener);
        }
    }

    private void notifyInvalidation() {
        for (Runnable r : invalidationListeners) {
            try {
                r.run();
            } catch (Exception ignored) {
            }
        }
    }

    public void ensureIndexes(String graph) {
        if (graph == null) {
            return;
        }
        if (!indexedGraphs.add(graph)) {
            return;
        }
        for (String label : LABELS) {
            try {
                graphs.write(graph, "CREATE INDEX FOR (n:" + label + ") ON (n.id)", Map.of());
            } catch (Exception ignored) {
            }
        }
    }

    @Override
    public void afterPropertiesSet() {
        try {
            ensureIndexes(graphs.main());
        } catch (Exception ignored) {
        }
    }

    public SourceSet lastSources() {
        return lastSources;
    }

    public List<String> lastWarnings() {
        return Collections.unmodifiableList(lastWarnings);
    }

    public int lastPrunedPaths() {
        return lastPrunedPaths;
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
            String url = "https://api.github.com/repos/" + owner + "/" + repo + "/contents/.github/workflows";
            JsonNode listing = json.readTree(get(url, "application/vnd.github+json", String.class));
            record DownloadTarget(String name, String url) {}
            List<DownloadTarget> targets = new ArrayList<>();
            for (JsonNode f : listing) {
                String name = f.path("name").asText();
                String fileUrl = f.path("url").asText("");
                if ((name.endsWith(".yml") || name.endsWith(".yaml")) && !fileUrl.isBlank()) {
                    targets.add(new DownloadTarget(name, fileUrl));
                }
            }

            if (!targets.isEmpty()) {
                ExecutorService pool = Executors.newFixedThreadPool(Math.min(targets.size(), 5));
                try {
                    List<Future<WorkflowFile>> futures = new ArrayList<>();
                    for (DownloadTarget t : targets) {
                        futures.add(pool.submit(() -> {
                            String content = get(t.url(), "application/vnd.github.raw", String.class);
                            return new WorkflowFile(owner + "/" + repo, ".github/workflows/" + t.name(), content);
                        }));
                    }
                    for (Future<WorkflowFile> fut : futures) {
                        try {
                            files.add(fut.get());
                        } catch (ExecutionException ee) {
                            Throwable cause = ee.getCause() != null ? ee.getCause() : ee;
                            if (cause instanceof RuntimeException re) {
                                throw re;
                            }
                            if (cause instanceof Error err) {
                                throw err;
                            }
                            throw new RuntimeException(cause);
                        }
                    }
                } finally {
                    pool.shutdown();
                    try {
                        if (!pool.awaitTermination(30, TimeUnit.SECONDS)) {
                            pool.shutdownNow();
                        }
                    } catch (InterruptedException ie) {
                        pool.shutdownNow();
                        Thread.currentThread().interrupt();
                    }
                }
            }
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode().value() == 403 || e.getStatusCode().value() == 429) {
                log.error("GitHub API rate limit exceeded ({}) for {}/{}: {}", e.getStatusCode().value(), owner, repo, e.getMessage(), e);
                throw new IllegalArgumentException("GitHub API rate limit exceeded (" + e.getStatusCode().value() + "). Set GITHUB_TOKEN environment variable to raise the rate limit.", e);
            }
            log.error("Could not read .github/workflows of {}/{}: {}: {}", owner, repo, e.getClass().getName(), e.getMessage(), e);
            throw new IllegalArgumentException("Could not read .github/workflows of " + owner + "/" + repo + ": " + e.getClass().getName() + ": " + e.getMessage(), e);
        } catch (SecurityException se) {
            log.error("SecurityException accessing .github/workflows of {}/{}: {}", owner, repo, se.getMessage(), se);
            throw se;
        } catch (Exception e) {
            log.error("Could not read .github/workflows of {}/{}: {}: {}", owner, repo, e.getClass().getName(), e.getMessage(), e);
            String msg = e.getMessage() != null ? e.getMessage() : "";
            if (msg.contains("403") || msg.contains("429") || msg.toLowerCase().contains("rate limit")) {
                throw new IllegalArgumentException("GitHub API rate limit exceeded. Set GITHUB_TOKEN environment variable to raise the rate limit.", e);
            }
            throw new IllegalArgumentException("Could not read .github/workflows of " + owner + "/" + repo + ": " + e.getClass().getName() + ": " + e.getMessage(), e);
        }
        if (files.isEmpty()) {
            throw new IllegalArgumentException("No workflow files found in " + owner + "/" + repo);
        }
        String currentIam = (userUploadedIam != null && !userUploadedIam.isBlank()) ? userUploadedIam : "";
        iamStatus = (userUploadedIam != null && !userUploadedIam.isBlank()) ? "uploaded" : "none";
        return new SourceSet(files, currentIam);
    }

    public synchronized void loadMain(SourceSet src) {
        lastSources = src;
        if (src.iamJson() == null || src.iamJson().isBlank()) {
            iamStatus = "none";
        } else if (userUploadedIam != null && userUploadedIam.equals(src.iamJson())) {
            iamStatus = "uploaded";
        } else if (src.iamJson().equals(sampleSources().iamJson())) {
            iamStatus = "demo";
        } else {
            iamStatus = "uploaded";
        }
        ingest(graphs.main(), src, true);
        notifyInvalidation();
    }

    public synchronized void loadIam(String iamJson) {
        userUploadedIam = iamJson;
        iamStatus = (iamJson != null && !iamJson.isBlank()) ? "uploaded" : "none";
        SourceSet current = lastSources != null ? lastSources : sampleSources();
        SourceSet updated = new SourceSet(current.workflows(), iamJson != null ? iamJson : "");
        loadMain(updated);
    }

    public void buildSim(String simGraph) {
        if (lastSources == null) {
            throw new IllegalStateException("Load data first");
        }
        ingest(simGraph, lastSources, false);
    }

    private void ingest(String graph, SourceSet src, boolean reset) {
        ensureIndexes(graph);
        if (reset) {
            graphs.write(graph, "MATCH (n) WHERE NOT 'Decision' IN labels(n) AND NOT 'Finding' IN labels(n) DETACH DELETE n", Map.of());
            lastWarnings.clear();
            lastPrunedPaths = 0;
        }

        Map<String, ParsedRole> importedRoles = ingestIam(graph, src.iamJson());
        for (WorkflowFile wf : src.workflows()) {
            ingestWorkflow(graph, wf, importedRoles);
        }
        if (reset) {
            relinkMemory(graph);
        }
        if (graph.equals(graphs.main())) {
            notifyInvalidation();
        }
    }

    public void relinkMemory(String graph) {
        try {
            graphs.write(graph, "MATCH (d:Decision) WHERE d.targets IS NOT NULL UNWIND d.targets AS tid MATCH (n {id: tid}) MERGE (d)-[:APPLIES_TO]->(n)", Map.of());
            graphs.write(graph, "MATCH (f:Finding) WHERE f.targets IS NOT NULL UNWIND f.targets AS tid MATCH (n {id: tid}) MERGE (f)-[:ABOUT]->(n)", Map.of());
        } catch (Exception ignored) {
        }
    }

    private Map<String, ParsedRole> ingestIam(String g, String iamJson) {
        if (iamJson == null || iamJson.isBlank()) {
            return Map.of();
        }
        if (awsIamService.isAwsAuthDetails(iamJson)) {
            return ingestAwsAuthDetails(g, iamJson);
        }
        return ingestSampleIam(g, iamJson);
    }

    private Map<String, ParsedRole> ingestAwsAuthDetails(String g, String iamJson) {
        IamParseResult result = awsIamService.parseAuthorizationDetails(iamJson);
        lastWarnings.addAll(result.warnings());

        Map<String, ParsedRole> uniqueRoles = new LinkedHashMap<>();
        for (ParsedRole r : result.roles().values()) {
            uniqueRoles.putIfAbsent(r.name(), r);
        }

        // 1. Create Role nodes
        for (ParsedRole r : uniqueRoles.values()) {
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("name", r.name());
            props.put("arn", r.arn());
            props.put("isAdmin", r.isAdmin());
            props.put("overPermissiveOidc", r.oidcTrust().overPermissive());
            node(g, "Role", "role:" + r.name(), props);

            if (r.oidcTrust().overPermissive()) {
                lastWarnings.add("Over-broad OIDC trust on role '" + r.name() + "': " + r.oidcTrust().overPermissiveReason());
            }
        }

        // 2. Create Resource nodes
        for (ParsedResource res : result.resources().values()) {
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("name", res.name());
            props.put("type", res.type());
            props.put("sensitive", res.sensitive());
            if (!res.arn().isEmpty()) props.put("arn", res.arn());
            node(g, "Resource", "resource:" + res.name(), props);
            if (!res.executesAsRole().isEmpty()) {
                edge(g, "Resource", "resource:" + res.name(), "EXECUTES_AS", "Role", "role:" + res.executesAsRole());
            }
        }

        // 3. Connect Role -> Role edges (CAN_ASSUME, CAN_PASS_ROLE)
        for (ParsedRole from : uniqueRoles.values()) {
            String fromId = "role:" + from.name();
            boolean canCompute = awsIamService.canCreateCompute(from.statements());

            for (ParsedRole to : uniqueRoles.values()) {
                if (from.name().equalsIgnoreCase(to.name())) continue;
                String toId = "role:" + to.name();

                // Direct permission: from has sts:AssumeRole for to
                boolean directAssume = awsIamService.checkPermission(from.statements(), "sts:AssumeRole", to.arn().isEmpty() ? to.name() : to.arn());
                // Trust policy: to trusts from's ARN
                boolean trustAssume = to.trustedRoleArns().contains(from.arn()) || to.trustedRoleArns().contains(from.name());

                if (directAssume || trustAssume) {
                    edge(g, "Role", fromId, "CAN_ASSUME", "Role", toId);
                }

                // PassRole
                boolean passRole = awsIamService.checkPermission(from.statements(), "iam:PassRole", to.arn().isEmpty() ? to.name() : to.arn())
                        || awsIamService.checkPermission(from.statements(), "iam:PassRole", "*");
                if (canCompute && passRole) {
                    edge(g, "Role", fromId, "CAN_PASS_ROLE", "Role", toId);
                }
            }

            // 4. Role -> Resource (CAN_UPDATE_CODE, CAN_ACCESS)
            for (ParsedResource res : result.resources().values()) {
                String toId = "resource:" + res.name();
                String target = res.arn().isEmpty() ? res.name() : res.arn();

                if ("lambda".equalsIgnoreCase(res.type()) && awsIamService.checkPermission(from.statements(), "lambda:UpdateFunctionCode", target)) {
                    edge(g, "Role", fromId, "CAN_UPDATE_CODE", "Resource", toId);
                }

                Set<String> grantedActions = new TreeSet<>();
                for (PolicyStatement stmt : from.statements()) {
                    if (stmt.isAllow()) {
                        for (String act : stmt.actions()) {
                            if (!act.toLowerCase().startsWith("iam:") && !act.toLowerCase().startsWith("sts:")
                                    && COMPUTE_ACTIONS.stream().noneMatch(c -> c.equalsIgnoreCase(act))
                                    && serviceMatches(act, res.type())) {
                                if (awsIamService.checkPermission(from.statements(), act, target)) {
                                    grantedActions.add(act);
                                }
                            }
                        }
                    }
                }
                if (!grantedActions.isEmpty()) {
                    edge(g, "Role", fromId, "CAN_ACCESS", "Resource", toId, Map.of("actions", String.join(",", grantedActions)));
                }
            }
        }
        return uniqueRoles;
    }

    private Map<String, ParsedRole> ingestSampleIam(String g, String iamJson) {
        JsonNode root;
        try {
            root = json.readTree(iamJson);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid IAM JSON: " + e.getMessage());
        }
        List<String> roles = new ArrayList<>();
        Map<String, String> resourceType = new LinkedHashMap<>();
        Map<String, ParsedRole> roleMap = new LinkedHashMap<>();

        for (JsonNode r : root.path("roles")) {
            String name = r.path("name").asText();
            roles.add(name);
            boolean isAdmin = r.path("admin").asBoolean(false);
            node(g, "Role", "role:" + name, Map.of("name", name, "isAdmin", isAdmin));
            roleMap.put(name, new ParsedRole(name, "arn:aws:iam::111111111111:role/" + name, isAdmin,
                    new AwsIamService.OidcTrustInfo(false, "", List.of(), false, false, null),
                    List.of(), Set.of(), Set.of()));
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
        return roleMap;
    }

    private void ingestWorkflow(String g, WorkflowFile wf, Map<String, ParsedRole> importedRoles) {
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
        String branch = null;

        if (on.isTextual()) {
            events.add(on.asText());
        } else if (on.isArray()) {
            on.forEach(x -> events.add(x.asText()));
        } else if (on.isObject()) {
            on.fieldNames().forEachRemaining(events::add);
            if (on.has("push") && on.path("push").has("branches")) {
                JsonNode brs = on.path("push").path("branches");
                if (brs.isArray() && brs.size() > 0) branch = brs.get(0).asText();
            }
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

            // P1-5 Matrix expansion check
            Map<String, Object> jobProps = new LinkedHashMap<>();
            jobProps.put("name", jobName);
            jobProps.put("permissions", permText);
            JsonNode matrix = job.path("strategy").path("matrix");
            if (matrix.isObject() && matrix.size() > 0) {
                List<String> matrixKeys = new ArrayList<>();
                matrix.fieldNames().forEachRemaining(matrixKeys::add);
                jobProps.put("matrix", String.join(",", matrixKeys));
            }
            node(g, "Job", jobId, jobProps);
            edge(g, "Workflow", wfId, "RUNS_JOB", "Job", jobId);

            // Reusable workflow called directly as a job (uses: ./.github/workflows/x.yml or uses: org/repo/...)
            String jobUses = job.path("uses").asText("");
            if (!jobUses.isEmpty()) {
                String targetWfId = resolveWorkflowReference(wf.repo(), jobUses);
                node(g, "Workflow", targetWfId, Map.of("name", extractWorkflowName(jobUses), "path", jobUses, "reusable", true));
                edge(g, "Job", jobId, "CALLS_WORKFLOW", "Workflow", targetWfId);
            }

            for (JsonNode step : job.path("steps")) {
                String uses = step.path("uses").asText("");
                if (uses.isEmpty() || uses.startsWith("docker://")) {
                    continue;
                }

                // P1-5: Reusable workflow called from a step
                if (uses.startsWith("./.github/workflows/") || uses.contains("/.github/workflows/")) {
                    String targetWfId = resolveWorkflowReference(wf.repo(), uses);
                    node(g, "Workflow", targetWfId, Map.of("name", extractWorkflowName(uses), "path", uses, "reusable", true));
                    edge(g, "Job", jobId, "CALLS_WORKFLOW", "Workflow", targetWfId);
                    continue;
                }
                if (uses.startsWith("./")) {
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
                    if (!arn.isEmpty()) {
                        String roleName = extractRoleName(arn);
                        ParsedRole parsedRole = importedRoles.get(roleName);
                        if (parsedRole == null && !arn.isEmpty()) {
                            parsedRole = importedRoles.get(arn);
                        }

                        if (parsedRole == null) {
                            if (!arn.contains("${{")) {
                                lastWarnings.add("Unmatched role in workflow " + wf.path() + ", job '" + jobName + "': " + arn);
                            }
                            node(g, "Role", "role:" + roleName, Map.of("name", roleName));
                            edge(g, "Job", jobId, "ASSUMES", "Role", "role:" + roleName);
                        } else {
                            // P1-2: Validate OIDC trust
                            if (parsedRole.oidcTrust().trustsGithub()) {
                                boolean matches = awsIamService.matchesOidc(parsedRole.oidcTrust(), wf.repo(), events, branch);
                                if (matches) {
                                    node(g, "Role", "role:" + parsedRole.name(), Map.of("name", parsedRole.name()));
                                    edge(g, "Job", jobId, "ASSUMES", "Role", "role:" + parsedRole.name());
                                } else {
                                    lastPrunedPaths++;
                                    log.info("Pruned ASSUMES edge from job {} to role {}: OIDC trust condition not met", jobId, parsedRole.name());
                                }
                            } else {
                                node(g, "Role", "role:" + parsedRole.name(), Map.of("name", parsedRole.name()));
                                edge(g, "Job", jobId, "ASSUMES", "Role", "role:" + parsedRole.name());
                            }
                        }
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

    private String extractRoleName(String arn) {
        if (arn.contains("role/")) {
            return arn.substring(arn.lastIndexOf("role/") + 5);
        }
        if (arn.contains("/")) {
            return arn.substring(arn.lastIndexOf('/') + 1);
        }
        if (arn.contains(":")) {
            return arn.substring(arn.lastIndexOf(':') + 1);
        }
        return arn;
    }

    private String resolveWorkflowReference(String repo, String ref) {
        if (ref.startsWith("./")) {
            return "wf:" + repo + ":" + ref.substring(2);
        }
        int at = ref.indexOf('@');
        String base = at > 0 ? ref.substring(0, at) : ref;
        return "wf:" + base;
    }

    private String extractWorkflowName(String ref) {
        int slash = ref.lastIndexOf('/');
        String name = slash >= 0 ? ref.substring(slash + 1) : ref;
        int at = name.indexOf('@');
        return at > 0 ? name.substring(0, at) : name;
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
        if (type == null || type.isBlank() || type.equals("unknown")) return true;
        String svc = action.contains(":") ? action.substring(0, action.indexOf(':')) : action;
        return svc.equals("*") || glob(svc, type);
    }

    static boolean glob(String pattern, String text) {
        String regex = Arrays.stream(pattern.split("\\*", -1)).map(Pattern::quote).collect(Collectors.joining(".*"));
        return Pattern.compile("^" + regex + "$", Pattern.CASE_INSENSITIVE).matcher(text).matches();
    }

    private <T> T get(String url, String acceptHeader, Class<T> type) {
        URI uri = URI.create(url);
        validateGithubHost(uri);
        return http.get().uri(uri)
                .header("Accept", acceptHeader)
                .headers(h -> {
                    if (!githubToken.isBlank()) {
                        h.setBearerAuth(githubToken);
                    }
                })
                .retrieve().body(type);
    }

    void validateGithubHost(URI uri) {
        String host = uri.getHost();
        if (host == null || !host.equalsIgnoreCase("api.github.com")) {
            throw new SecurityException("SSRF blocked: Disallowed host " + host);
        }
    }
}