 package com.graphguard;

import com.graphguard.Models.AgentAnswer;
import com.graphguard.Models.AskRequest;
import com.graphguard.Models.AttackPath;
import com.graphguard.Models.DecisionRequest;
import com.graphguard.Models.Edge;
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
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {
    private final GraphService graphs;
    private final Ingestor ingestor;
    private final AnalysisService analysis;
    private final AgentService agent;

    public ApiController(GraphService graphs, Ingestor ingestor, AnalysisService analysis, AgentService agent) {
        this.graphs = graphs;
        this.ingestor = ingestor;
        this.analysis = analysis;
        this.agent = agent;
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
    public List<AttackPath> paths() {
        return analysis.findPaths(graphs.main());
    }

    @GetMapping("/blast-radius")
    public Map<String, Object> blast(@RequestParam String node, @RequestParam(defaultValue = "4") int depth) {
        return analysis.blastRadius(graphs.main(), node, depth);
    }

    @GetMapping("/choke-points")
    public Map<String, Object> choke() {
        return analysis.chokePoints(graphs.main());
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
                ((List<?>) g.get("edges")).size(), analysis.findPaths(graphs.main()).size());
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