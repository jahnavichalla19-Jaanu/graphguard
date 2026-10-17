package com.graphguard;

import java.util.List;
import java.util.Map;

public final class Models {
    private Models() {
    }

    public record WorkflowFile(String repo, String path, String yaml) {}
    public record SourceSet(List<WorkflowFile> workflows, String iamJson) {}
    public record Edge(String source, String type, String target) {}
    public record AttackPath(
            String key,
            int length,
            List<String> nodeIds,
            List<String> nodeNames,
            List<String> nodeLabels,
            List<String> edgeTypes,
            List<String> explanation,
            boolean accepted,
            String acceptedBy,
            double riskScore,
            String severity,
            String riskReason
    ) {
        public AttackPath(String key, int length, List<String> nodeIds, List<String> nodeNames, List<String> nodeLabels,
                          List<String> edgeTypes, List<String> explanation, boolean accepted, String acceptedBy) {
            this(key, length, nodeIds, nodeNames, nodeLabels, edgeTypes, explanation, accepted, acceptedBy, 5.0, "medium", "Standard attack path");
        }
    }

    public record RankedNode(String id, String name, String label, int paths) {}
    public record RankedEdge(String source, String type, String target, String description, int paths) {}
    public record SimResult(Edge edge, int before, int after, List<String> removedKeys, List<String> newKeys,
                            boolean edgeExisted, String proposal, long millis) {}
    public record IngestStats(int workflows, int nodes, int edges, int paths, int prunedPaths, List<String> warnings) {
        public IngestStats(int workflows, int nodes, int edges, int paths) {
            this(workflows, nodes, edges, paths, 0, List.of());
        }
    }
    public record AskRequest(String question) {}
    public record GithubRequest(String owner, String repo) {}
    public record DecisionRequest(String pathKey, String owner, String reason, Integer days) {}
    public record FindingRequest(String node, String text) {}
    public record AgentAnswer(String answer, List<Map<String, Object>> toolCalls, List<List<String>> highlightPaths, String mode, String outcome, List<ClaimCitation> claims, boolean verified) {
        public AgentAnswer(String answer, List<Map<String, Object>> toolCalls, List<List<String>> highlightPaths, String mode, String outcome) {
            this(answer, toolCalls, highlightPaths, mode, outcome, List.of(), false);
        }
    }
    public record ClaimCitation(String claim, List<String> nodeIds, List<String> pathKeys, boolean verified) {}
    public record RuleFinding(String ruleId, String severity, String title, String description, String remediation, String targetId, String targetName, String file, Integer line) {}
    public record PatchSuggestion(String ruleId, String file, String description, String unifiedDiff) {}
}