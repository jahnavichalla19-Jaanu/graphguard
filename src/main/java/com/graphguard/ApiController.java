package com.graphguard;

import com.graphguard.Models.AgentAnswer;
import com.graphguard.Models.AskRequest;
import com.graphguard.Models.AttackPath;
import com.graphguard.Models.DecisionRequest;
import com.graphguard.Models.Edge;
import com.graphguard.Models.FindingRequest;
import com.graphguard.Models.GithubRequest;
import com.graphguard.Models.IngestStats;
import com.graphguard.Models.SimResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {
    private final GraphService graphs;
    private final Ingestor ingestor;
    private final AnalysisService analysis;
    private final AgentService agent;
    private final boolean awsLive;

    public ApiController(GraphService graphs, Ingestor ingestor, AnalysisService analysis, AgentService agent,
                         @Value("${graphguard.aws.live:false}") boolean awsLive) {
        this.graphs = graphs;
        this.ingestor = ingestor;
        this.analysis = analysis;
        this.agent = agent;
        this.awsLive = awsLive;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        graphs.query(graphs.main(), "RETURN 1 AS ok", Map.of());
        return Map.of("status", "ok", "graph", graphs.main());
    }

    @PostMapping("/ingest/sample")
    public IngestStats sample() {
        ingestor.loadMain(ingestor.sampleSources());
        return stats();
    }

    @PostMapping(value = "/ingest/aws-iam", consumes = {"application/json", "text/plain", "*/*"})
    public IngestStats awsIamJson(@RequestBody(required = false) String body) {
        if (body == null || body.isBlank()) {
            throw new IllegalArgumentException("IAM JSON payload cannot be empty");
        }
        ingestor.loadIam(body);
        return stats();
    }

    @PostMapping(value = "/ingest/aws-iam", consumes = "multipart/form-data")
    public IngestStats awsIamMultipart(@RequestParam("file") MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Uploaded IAM file cannot be empty");
        }
        String content = new String(file.getBytes(), StandardCharsets.UTF_8);
        ingestor.loadIam(content);
        return stats();
    }

    @PostMapping("/ingest/aws-live")
    public IngestStats awsLive() {
        if (!awsLive) {
            throw new IllegalArgumentException("Live AWS ingestion is disabled by default. Set GRAPHGUARD_AWS_LIVE=true in the environment to use the default AWS credential chain, or import an IAM dump via POST /api/ingest/aws-iam (no credentials required).");
        }
        throw new UnsupportedOperationException("Live AWS credentials chain could not discover valid active session in environment.");
    }

    @PostMapping("/ingest/github")
    public IngestStats github(@RequestBody GithubRequest r) {
        ingestor.loadMain(ingestor.githubSources(r.owner(), r.repo()));
        return stats();
    }

    @GetMapping("/graph")
    public Map<String, Object> graph() {

        return analysis.graph(graphs.main());
    }

    @GetMapping("/paths")
    public List<AttackPath> paths(@RequestParam(required = false) String minSeverity,
                                  @RequestParam(required = false) String entry) {
        return analysis.findPaths(graphs.main(), minSeverity, entry, minSeverity != null || entry != null);
    }

    @GetMapping("/findings")
    public List<com.graphguard.Models.RuleFinding> ruleFindings() {
        return analysis.findings(graphs.main());
    }

    @GetMapping("/patches")
    public List<com.graphguard.Models.PatchSuggestion> patchSuggestions() {
        return analysis.patches(graphs.main());
    }

    @GetMapping("/blast-radius")
    public Map<String, Object> blast(@RequestParam String node, @RequestParam(defaultValue = "4") int depth) {
        return analysis.blastRadius(graphs.main(), node, depth);
    }

    @GetMapping("/path-between")
    public Map<String, Object> pathBetween(@RequestParam String from, @RequestParam String to) {
        return analysis.pathBetween(graphs.main(), from, to);
    }

    @GetMapping("/load-bearing")
    public Map<String, Object> loadBearing(@RequestParam(defaultValue = "5") int limit) {
        return analysis.loadBearing(graphs.main(), limit);
    }

    @GetMapping("/choke-points")
    public Map<String, Object> choke() {
        return analysis.chokePoints(graphs.main());
    }

    @GetMapping("/recall")
    public Map<String, Object> recall(@RequestParam String node) {
        return analysis.recall(graphs.main(), node);
    }

    @PostMapping("/findings")
    public Map<String, Object> findings(@RequestBody FindingRequest r) {
        return analysis.saveFinding(graphs.main(), r.node(), r.text());
    }

    @PostMapping("/simulate-fix")
    public SimResult simulate(@RequestBody Edge edge) {
        return analysis.simulate(edge);
    }

    @PostMapping("/decisions")
    public Map<String, String> decide(@RequestBody DecisionRequest r) {
        analysis.acceptRisk(graphs.main(), r.pathKey(), r.owner() == null ? "unknown" : r.owner(), r.reason() == null ? "" : r.reason(), r.days() == null ? 30 : r.days());
        return Map.of("status", "recorded");
    }

    @PostMapping("/agent/ask")
    public AgentAnswer ask(@RequestBody AskRequest r) {
        return agent.ask(r.question());
    }

    private IngestStats stats() {
        Map<String, Object> g = analysis.graph(graphs.main());
        return new IngestStats(ingestor.lastSources().workflows().size(), ((List<?>) g.get("nodes")).size(),
                ((List<?>) g.get("edges")).size(), analysis.findPaths(graphs.main()).size(),
                ingestor.lastPrunedPaths(), ingestor.lastWarnings());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> badRequest(IllegalArgumentException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", String.valueOf(e.getMessage())));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> failure(Exception e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", String.valueOf(e.getMessage())));
    }
}