package com.graphguard;

import java.util.List;
import java.util.Map;

public final class Models {
    private Models() {
    }

    public record WorkflowFile(String repo, String path, String yaml) {}
    public record SourceSet(List<WorkflowFile> workflows, String iamJson) {}
    public record Edge(String source, String type, String target) {}
    public record AttackPath(String key, int length, List<String> nodeIds, List<String> nodeNames, List<String> nodeLabels,
                             List<String> edgeTypes, List<String> explanation, boolean accepted, String acceptedBy) {}
    public record RankedNode(String id, String name, String label, int paths) {}
    public record RankedEdge(String source, String type, String target, String description, int paths) {}
    public record SimResult(Edge edge, int before, int after, List<String> removedKeys, List<String> newKeys,
                            boolean edgeExisted, String proposal, long millis) {}
    public record IngestStats(int workflows, int nodes, int edges, int paths) {}
    public record AskRequest(String question) {}
    public record GithubRequest(String owner, String repo) {}
    public record DecisionRequest(String pathKey, String owner, String reason, Integer days) {}
    public record AgentAnswer(String answer, List<Map<String, Object>> toolCalls, List<List<String>> highlightPaths, String mode) {}
}