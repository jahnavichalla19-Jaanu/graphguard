package com.graphguard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.graphguard.AwsIamService.IamParseResult;
import com.graphguard.AwsIamService.ParsedRole;
import com.graphguard.AwsIamService.PolicyStatement;
import com.graphguard.Models.AttackPath;
import com.graphguard.Models.PatchSuggestion;
import com.graphguard.Models.RuleFinding;
import com.graphguard.Models.SourceSet;
import com.graphguard.Models.WorkflowFile;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class DetectionEngine {
    private static final Pattern SHA_PATTERN = Pattern.compile("^[0-9a-f]{40}$", Pattern.CASE_INSENSITIVE);
    private static final Pattern UNTRUSTED_INTERPOLATION = Pattern.compile(
            "\\$\\{\\{\\s*github\\.(event\\.(issue|pull_request|comment|review|head_commit|commits|workflow_run)\\.[A-Za-z0-9_.-]+|head_ref)\\s*\\}\\}",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SECRET_PATTERN = Pattern.compile("\\$\\{\\{\\s*secrets\\.([A-Za-z0-9_]+)\\s*\\}\\}");
    private static final Set<String> UNTRUSTED_TRIGGERS = Set.of("pull_request_target", "issue_comment", "workflow_run");
    private static final Set<String> COMPUTE_ACTIONS = Set.of("lambda:CreateFunction", "ec2:RunInstances", "cloudformation:CreateStack", "glue:CreateDevEndpoint");

    private final ObjectMapper yaml = new ObjectMapper(new YAMLFactory());
    private final AwsIamService awsIamService;

    public DetectionEngine(AwsIamService awsIamService) {
        this.awsIamService = awsIamService != null ? awsIamService : new AwsIamService();
    }

    public List<RuleFinding> scanAll(SourceSet sources) {
        List<RuleFinding> findings = new ArrayList<>();
        if (sources == null) return findings;
        if (sources.workflows() != null) {
            findings.addAll(scanWorkflows(sources.workflows()));
        }
        if (sources.iamJson() != null && !sources.iamJson().isBlank() && awsIamService.isAwsAuthDetails(sources.iamJson())) {
            IamParseResult iam = awsIamService.parseAuthorizationDetails(sources.iamJson());
            findings.addAll(scanIam(iam));
        }
        return findings;
    }

    public List<RuleFinding> scanWorkflows(List<WorkflowFile> workflows) {
        List<RuleFinding> findings = new ArrayList<>();
        for (WorkflowFile wf : workflows) {
            findings.addAll(scanWorkflow(wf));
        }
        return findings;
    }

    public List<RuleFinding> scanWorkflow(WorkflowFile wf) {
        List<RuleFinding> findings = new ArrayList<>();
        JsonNode doc;
        try {
            doc = yaml.readTree(wf.yaml());
        } catch (Exception e) {
            return findings;
        }

        JsonNode on = doc.has("on") ? doc.get("on") : doc.path("true");
        Set<String> triggers = extractTriggers(on);
        boolean hasPrTarget = triggers.contains("pull_request_target");
        boolean hasUntrustedTrigger = triggers.stream().anyMatch(UNTRUSTED_TRIGGERS::contains);

        JsonNode wfPerms = doc.path("permissions");
        boolean wfWriteAll = "write-all".equalsIgnoreCase(wfPerms.asText(""));
        boolean wfNoPerms = wfPerms.isMissingNode() || wfPerms.isNull();

        // GG-CI-005 Workflow level check
        if (hasUntrustedTrigger && (wfWriteAll || wfNoPerms)) {
            findings.add(new RuleFinding(
                    "GG-CI-005",
                    "medium",
                    "Permissive workflow permissions on privileged trigger",
                    "Workflow '" + wf.path() + "' runs on untrusted trigger " + triggers + " with " + (wfWriteAll ? "write-all permissions" : "no explicit permissions block (defaulting to read/write)"),
                    "Add an explicit 'permissions: contents: read' block at the top of the workflow.",
                    "wf:" + wf.repo() + ":" + wf.path(),
                    wf.path(),
                    wf.path(),
                    1
            ));
        }

        JsonNode jobs = doc.path("jobs");
        if (!jobs.isObject()) return findings;

        Iterator<Map.Entry<String, JsonNode>> it = jobs.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> entry = it.next();
            String jobName = entry.getKey();
            JsonNode job = entry.getValue();
            String jobId = "job:wf:" + wf.repo() + ":" + wf.path() + ":" + jobName;

            JsonNode jobPerms = job.path("permissions");
            boolean jobWriteAll = "write-all".equalsIgnoreCase(jobPerms.asText(""));

            // Check runs-on for GG-CI-006 (self-hosted)
            JsonNode runsOn = job.path("runs-on");
            boolean selfHosted = isSelfHosted(runsOn);
            if (selfHosted) {
                findings.add(new RuleFinding(
                        "GG-CI-006",
                        "high",
                        "Self-hosted runner execution on public or PR-accessible workflow",
                        "Job '" + jobName + "' in '" + wf.path() + "' executes on a self-hosted runner which can allow persistent lateral compromise if untrusted code runs.",
                        "Use GitHub-hosted runners or ephemeral runner groups isolated from production infrastructure.",
                        jobId,
                        jobName,
                        wf.path(),
                        null
                ));
            }

            JsonNode steps = job.path("steps");
            if (!steps.isArray()) continue;

            boolean jobHasSecret = SECRET_PATTERN.matcher(job.toString()).find();
            boolean jobHasWriteToken = jobWriteAll || wfWriteAll || hasWritePermissions(jobPerms) || hasWritePermissions(wfPerms);

            // GG-CI-003: Privileged trigger with secrets or write token
            if (hasUntrustedTrigger && (jobHasSecret || jobHasWriteToken)) {
                findings.add(new RuleFinding(
                        "GG-CI-003",
                        "high",
                        "Privileged trigger exposing repository secrets or write token",
                        "Job '" + jobName + "' in '" + wf.path() + "' triggers on " + triggers + " and accesses " + (jobHasSecret ? "secrets" : "write tokens") + ".",
                        "Separate privileged deployment steps into a separate workflow requiring maintainer approval or run only on push to main.",
                        jobId,
                        jobName,
                        wf.path(),
                        null
                ));
            }

            for (int sIdx = 0; sIdx < steps.size(); sIdx++) {
                JsonNode step = steps.get(sIdx);
                String uses = step.path("uses").asText("");
                String run = step.path("run").asText("");

                // GG-CI-001: pull_request_target + checkout of head
                if (hasPrTarget && uses.startsWith("actions/checkout")) {
                    String ref = step.path("with").path("ref").asText("");
                    if (ref.contains("github.event.pull_request.head") || ref.contains("github.head_ref")) {
                        findings.add(new RuleFinding(
                                "GG-CI-001",
                                "critical",
                                "pull_request_target with checkout of untrusted PR head",
                                "Step in job '" + jobName + "' checks out untrusted code from pull request head (" + ref + ") under pull_request_target.",
                                "Do not checkout the PR head in pull_request_target. Use pull_request instead, or checkout the default base branch.",
                                jobId,
                                jobName,
                                wf.path(),
                                sIdx + 1
                        ));
                    }
                }

                // GG-CI-002: Untrusted event interpolated into run
                if (!run.isEmpty()) {
                    boolean matches = run.contains("${{ github.event.") || run.contains("${{github.event.")
                            || run.contains("${{ github.head_ref") || run.contains("${{github.head_ref")
                            || UNTRUSTED_INTERPOLATION.matcher(run).find();
                    if (matches) {
                        findings.add(new RuleFinding(
                                "GG-CI-002",
                                "high",
                                "Untrusted github.event context interpolated into run script",
                                "Step in job '" + jobName + "' interpolates untrusted GitHub event context directly into shell command: " + truncate(run, 80),
                                "Pass untrusted values via step environment variables (env:) instead of inline ${{ ... }} interpolation.",
                                jobId,
                                jobName,
                                wf.path(),
                                sIdx + 1
                        ));
                    }
                }

                // GG-CI-004: Unpinned third-party action
                if (!uses.isEmpty() && !uses.startsWith("./") && !uses.startsWith("docker://")) {
                    int at = uses.lastIndexOf('@');
                    String actionName = at > 0 ? uses.substring(0, at) : uses;
                    String ref = at > 0 ? uses.substring(at + 1) : "";
                    boolean isOfficial = actionName.startsWith("actions/") || actionName.startsWith("github/");
                    if (!isOfficial && !SHA_PATTERN.matcher(ref).matches()) {
                        findings.add(new RuleFinding(
                                "GG-CI-004",
                                "medium",
                                "Third-party action not pinned to full commit SHA",
                                "Action '" + uses + "' is third-party and pinned to mutable tag/branch '" + ref + "' instead of a 40-character commit SHA.",
                                "Pin the action to an immutable 40-character commit SHA, e.g. " + actionName + "@<sha>.",
                                "act:" + uses,
                                uses,
                                wf.path(),
                                sIdx + 1
                        ));
                    }
                }

                // GG-CI-007: ACTIONS_ALLOW_UNSECURE_COMMANDS
                String stepStr = step.toString();
                if (stepStr.contains("ACTIONS_ALLOW_UNSECURE_COMMANDS") || (doc.toString().contains("ACTIONS_ALLOW_UNSECURE_COMMANDS"))) {
                    findings.add(new RuleFinding(
                            "GG-CI-007",
                            "high",
                            "Insecure environment command execution enabled",
                            "Workflow enables ACTIONS_ALLOW_UNSECURE_COMMANDS which allows command injection via workflow stdout.",
                            "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and use environment files ($GITHUB_ENV, $GITHUB_OUTPUT).",
                            jobId,
                            jobName,
                            wf.path(),
                            sIdx + 1
                    ));
                }

                // GG-CI-008: Artifact poisoning via workflow_run
                if (triggers.contains("workflow_run") && (uses.contains("download-artifact") || run.contains("download-artifact"))) {
                    findings.add(new RuleFinding(
                            "GG-CI-008",
                            "high",
                            "Artifact poisoning in workflow_run",
                            "Job '" + jobName + "' runs under workflow_run and downloads artifacts from the triggering workflow run.",
                            "Do not execute scripts, binaries, or templates downloaded from unverified fork workflow runs.",
                            jobId,
                            jobName,
                            wf.path(),
                            sIdx + 1
                    ));
                }

                // GG-CI-009: Cache poisoning across trust boundaries
                if (hasUntrustedTrigger && uses.contains("actions/cache")) {
                    findings.add(new RuleFinding(
                            "GG-CI-009",
                            "medium",
                            "Cache poisoning across trust boundaries",
                            "Job '" + jobName + "' triggers on untrusted events and uses actions/cache without strict isolation.",
                            "Do not restore caches from untrusted pull request branches into privileged pipelines.",
                            jobId,
                            jobName,
                            wf.path(),
                            sIdx + 1
                    ));
                }
            }
        }
        return findings;
    }

    public List<RuleFinding> scanIam(IamParseResult iam) {
        List<RuleFinding> findings = new ArrayList<>();
        if (iam == null || iam.roles() == null) return findings;

        Set<String> inspectedRoles = new LinkedHashSet<>();
        for (ParsedRole role : iam.roles().values()) {
            if (!inspectedRoles.add(role.name())) continue;

            // GG-IAM-001: iam:PassRole + compute creation
            boolean hasPassRole = awsIamService.checkPermission(role.statements(), "iam:PassRole", "*");
            boolean hasCompute = awsIamService.canCreateCompute(role.statements());
            if (hasPassRole && hasCompute) {
                findings.add(new RuleFinding(
                        "GG-IAM-001",
                        "critical",
                        "Privilege escalation via iam:PassRole and compute creation",
                        "Role '" + role.name() + "' has both iam:PassRole and compute creation permissions, allowing privilege escalation.",
                        "Scope iam:PassRole to specific non-admin role ARNs and remove unnecessary compute creation capabilities.",
                        "role:" + role.name(),
                        role.name(),
                        "AWS IAM",
                        null
                ));
            }

            // GG-IAM-002: iam:* or *:* on Resource *
            if (role.isAdmin()) {
                findings.add(new RuleFinding(
                        "GG-IAM-002",
                        "critical",
                        "Over-privileged Administrator policy (wildcard on Resource: *)",
                        "Role '" + role.name() + "' grants full administrative control via AdministratorAccess or '*:*' on Resource '*'.",
                        "Replace full administrator access with fine-grained least-privilege roles.",
                        "role:" + role.name(),
                        role.name(),
                        "AWS IAM",
                        null
                ));
            }

            // GG-IAM-003: Over-broad OIDC trust
            if (role.oidcTrust().trustsGithub() && role.oidcTrust().overPermissive()) {
                findings.add(new RuleFinding(
                        "GG-IAM-003",
                        "high",
                        "Over-broad GitHub OIDC trust policy",
                        "Role '" + role.name() + "' has an over-permissive OIDC trust policy: " + role.oidcTrust().overPermissiveReason(),
                        "Restrict token.actions.githubusercontent.com:sub to exact repo and branch (e.g. repo:org/repo:ref:refs/heads/main).",
                        "role:" + role.name(),
                        role.name(),
                        "AWS IAM",
                        null
                ));
            }
        }
        return findings;
    }

    public AttackPath evaluatePathRisk(AttackPath path) {
        double score = 2.0;
        List<String> reasons = new ArrayList<>();

        String entry = path.nodeNames().isEmpty() ? "" : path.nodeNames().get(0);
        String target = path.nodeNames().isEmpty() ? "" : path.nodeNames().get(path.nodeNames().size() - 1);

        // Exploitability of entry trigger
        if (entry.equalsIgnoreCase("pull_request_target") || entry.equalsIgnoreCase("issue_comment")) {
            score += 3.5;
            reasons.add("Untrusted trigger '" + entry + "' can be initiated by external fork contributors");
        } else if (entry.equalsIgnoreCase("workflow_run")) {
            score += 2.0;
            reasons.add("Triggered by workflow_run from potentially untrusted PR context");
        } else if (entry.equalsIgnoreCase("pull_request")) {
            score += 1.5;
            reasons.add("Triggered by pull_request");
        } else {
            score += 1.0;
            reasons.add("Trigger '" + entry + "' requires internal repository permissions");
        }

        // Sensitive target
        if (target.contains("db") || target.contains("customer") || target.contains("prod") || target.contains("admin")) {
            score += 2.5;
            reasons.add("Reaches high-value production/customer asset '" + target + "'");
        } else {
            score += 1.0;
        }

        // Edge types
        if (path.edgeTypes().contains("CAN_PASS_ROLE") || path.edgeTypes().contains("CAN_UPDATE_CODE")) {
            score += 1.5;
            reasons.add("Involves compute privilege escalation or code replacement");
        }
        if (path.edgeTypes().contains("ASSUMES")) {
            score += 0.8;
            reasons.add("Bridges CI/CD execution into cloud IAM role");
        }

        // Hops count
        if (path.length() <= 3) {
            score += 0.5;
        }

        double finalScore = Math.min(10.0, Math.max(1.0, Math.round(score * 10.0) / 10.0));
        String severity;
        if (finalScore >= 8.5) severity = "critical";
        else if (finalScore >= 6.5) severity = "high";
        else if (finalScore >= 4.0) severity = "medium";
        else severity = "low";

        String reason = "Risk Score " + finalScore + " (" + severity.toUpperCase(Locale.ROOT) + "): " + String.join("; ", reasons);

        return new AttackPath(
                path.key(),
                path.length(),
                path.nodeIds(),
                path.nodeNames(),
                path.nodeLabels(),
                path.edgeTypes(),
                path.explanation(),
                path.accepted(),
                path.acceptedBy(),
                finalScore,
                severity,
                reason
        );
    }

    public List<AttackPath> scoreAndFilterPaths(List<AttackPath> rawPaths, String minSeverity, String entryFilter) {
        List<AttackPath> scored = rawPaths.stream().map(this::evaluatePathRisk).toList();

        List<AttackPath> filtered = scored.stream().filter(p -> {
            if (minSeverity != null && !minSeverity.isBlank()) {
                int minRank = severityRank(minSeverity);
                if (severityRank(p.severity()) < minRank) return false;
            }
            if (entryFilter != null && !entryFilter.isBlank()) {
                String entry = p.nodeNames().isEmpty() ? "" : p.nodeNames().get(0);
                if (!entry.equalsIgnoreCase(entryFilter) && !p.nodeIds().get(0).contains(entryFilter)) {
                    return false;
                }
            }
            return true;
        }).sorted(
                Comparator.comparingInt((AttackPath p) -> severityRank(p.severity())).reversed()
                        .thenComparing(Comparator.comparingDouble(AttackPath::riskScore).reversed())
                        .thenComparingInt(AttackPath::length)
                        .thenComparing(AttackPath::key)
        ).toList();

        return filtered;
    }

    private int severityRank(String s) {
        if (s == null) return 0;
        return switch (s.toLowerCase(Locale.ROOT)) {
            case "critical" -> 4;
            case "high" -> 3;
            case "medium" -> 2;
            case "low" -> 1;
            default -> 0;
        };
    }

    public PatchSuggestion generatePatch(RuleFinding finding, WorkflowFile wf) {
        String path = wf.path();
        String diff = switch (finding.ruleId()) {
            case "GG-CI-001" -> """
                    --- a/%s
                    +++ b/%s
                    @@ -3,2 +3,2 @@
                    -  pull_request_target:
                    +  pull_request:
                    """.formatted(path, path);
            case "GG-CI-002" -> """
                    --- a/%s
                    +++ b/%s
                    @@ -18,1 +18,3 @@
                    -      - run: echo "${{ github.event.pull_request.title }}"
                    +      - run: echo "$PR_TITLE"
                    +        env:
                    +          PR_TITLE: ${{ github.event.pull_request.title }}
                    """.formatted(path, path);
            case "GG-CI-004" -> """
                    --- a/%s
                    +++ b/%s
                    @@ -13,1 +13,1 @@
                    -      - uses: %s
                    +      - uses: %s@11bd71901bbe5b1630ceea73d27597364c9af683 # pinned SHA
                    """.formatted(path, path, finding.targetName(), finding.targetName().replaceAll("@[^@]+$", ""));
            case "GG-CI-005" -> """
                    --- a/%s
                    +++ b/%s
                    @@ -5,1 +5,2 @@
                    -permissions: write-all
                    +permissions:
                    +  contents: read
                    """.formatted(path, path);
            default -> """
                    --- a/%s
                    +++ b/%s
                    @@ -1,1 +1,1 @@
                    +# [Plan-Only] Remediation for %s: %s
                    """.formatted(path, path, finding.ruleId(), finding.remediation());
        };
        return new PatchSuggestion(finding.ruleId(), path, finding.remediation(), diff);
    }

    private Set<String> extractTriggers(JsonNode on) {
        Set<String> triggers = new LinkedHashSet<>();
        if (on == null || on.isMissingNode() || on.isNull()) return triggers;
        if (on.isTextual()) {
            triggers.add(on.asText());
        } else if (on.isArray()) {
            on.forEach(x -> triggers.add(x.asText()));
        } else if (on.isObject()) {
            on.fieldNames().forEachRemaining(triggers::add);
        }
        return triggers;
    }

    private boolean isSelfHosted(JsonNode runsOn) {
        if (runsOn.isTextual()) {
            return "self-hosted".equalsIgnoreCase(runsOn.asText());
        }
        if (runsOn.isArray()) {
            for (JsonNode n : runsOn) {
                if ("self-hosted".equalsIgnoreCase(n.asText())) return true;
            }
        }
        return false;
    }

    private boolean hasWritePermissions(JsonNode perms) {
        if (perms == null || perms.isMissingNode() || perms.isNull()) return false;
        if (perms.isTextual() && "write-all".equalsIgnoreCase(perms.asText())) return true;
        if (perms.isObject()) {
            Iterator<JsonNode> it = perms.elements();
            while (it.hasNext()) {
                if ("write".equalsIgnoreCase(it.next().asText())) return true;
            }
        }
        return false;
    }

    private static String truncate(String text, int max) {
        if (text == null) return "";
        String clean = text.replace("\n", " ").trim();
        return clean.length() > max ? clean.substring(0, max) + "..." : clean;
    }
}
