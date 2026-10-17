package com.graphguard;

import com.graphguard.AwsIamService.IamParseResult;
import com.graphguard.AwsIamService.ParsedRole;
import com.graphguard.AwsIamService.PolicyStatement;
import com.graphguard.Models.AttackPath;
import com.graphguard.Models.PatchSuggestion;
import com.graphguard.Models.RuleFinding;
import com.graphguard.Models.WorkflowFile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DetectionEngineTest {
    private DetectionEngine engine;
    private AwsIamService iamService;

    @BeforeEach
    public void setUp() {
        iamService = new AwsIamService();
        engine = new DetectionEngine(iamService);
    }

    private boolean hasFinding(List<RuleFinding> findings, String ruleId) {
        return findings.stream().anyMatch(f -> f.ruleId().equals(ruleId));
    }

    // GG-CI-001: pull_request_target + checkout of head
    @Test
    public void testRuleGgCi001PositiveAndNegative() {
        String vulnYaml = """
                name: PR Target Vuln
                on: pull_request_target
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/checkout@v4
                        with:
                          ref: ${{ github.event.pull_request.head.sha }}
                """;
        List<RuleFinding> vuln = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/vuln1.yml", vulnYaml));
        assertTrue(hasFinding(vuln, "GG-CI-001"), "Should detect GG-CI-001 on pull_request_target checking out PR head ref");

        String safeYaml = """
                name: Safe PR Checkout
                on: pull_request
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/checkout@v4
                        with:
                          ref: ${{ github.event.pull_request.head.sha }}
                """;
        List<RuleFinding> safe = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/safe1.yml", safeYaml));
        assertFalse(hasFinding(safe, "GG-CI-001"), "Standard pull_request event is safe from GG-CI-001");
    }

    // GG-CI-002: ${{ github.event.* }} interpolated into run:
    @Test
    public void testRuleGgCi002PositiveAndNegative() {
        String vulnYaml = """
                name: Script Injection
                on: push
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - run: |
                          echo "PR title is ${{ github.event.pull_request.title }}"
                """;
        List<RuleFinding> vuln = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/vuln2.yml", vulnYaml));
        assertTrue(hasFinding(vuln, "GG-CI-002"), "Should detect untrusted event interpolated into run script");

        String safeYaml = """
                name: Safe Environment Variable
                on: push
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - run: echo "PR title is: $PR_TITLE"
                        env:
                          PR_TITLE: ${{ github.event.pull_request.title }}
                """;
        List<RuleFinding> safe = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/safe2.yml", safeYaml));
        assertFalse(hasFinding(safe, "GG-CI-002"), "Environment variable passing is safe from GG-CI-002");
    }

    // GG-CI-003: issue_comment / pull_request_target with secrets
    @Test
    public void testRuleGgCi003PositiveAndNegative() {
        String vulnYaml = """
                name: Untrusted Comment
                on: issue_comment
                permissions:
                  contents: read
                jobs:
                  deploy:
                    runs-on: ubuntu-latest
                    steps:
                      - run: ./deploy.sh
                        env:
                          TOKEN: ${{ secrets.PROD_API_KEY }}
                """;
        List<RuleFinding> vuln = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/vuln3.yml", vulnYaml));
        assertTrue(hasFinding(vuln, "GG-CI-003"), "Should detect secrets on issue_comment trigger");

        String safeYaml = """
                name: Push Deploy
                on: push
                permissions:
                  contents: read
                jobs:
                  deploy:
                    runs-on: ubuntu-latest
                    steps:
                      - run: ./deploy.sh
                        env:
                          TOKEN: ${{ secrets.PROD_API_KEY }}
                """;
        List<RuleFinding> safe = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/safe3.yml", safeYaml));
        assertFalse(hasFinding(safe, "GG-CI-003"), "Push deploy with secrets is not an untrusted trigger violation");
    }

    // GG-CI-004: Third-party action not pinned to 40-char SHA
    @Test
    public void testRuleGgCi004PositiveAndNegative() {
        String vulnYaml = """
                name: Unpinned Action
                on: push
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: thirdparty-corp/security-check@v2
                """;
        List<RuleFinding> vuln = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/vuln4.yml", vulnYaml));
        assertTrue(hasFinding(vuln, "GG-CI-004"), "Should detect third-party action pinned to tag");

        String safeYaml = """
                name: Pinned Action
                on: push
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: thirdparty-corp/security-check@11bd71901bbe5b1630ceea73d27597364c9af683
                """;
        List<RuleFinding> safe = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/safe4.yml", safeYaml));
        assertFalse(hasFinding(safe, "GG-CI-004"), "40-character commit SHA is safe");
    }

    // GG-CI-005: permissions: write-all or missing on privileged triggers
    @Test
    public void testRuleGgCi005PositiveAndNegative() {
        String vulnYaml = """
                name: Write All Perms
                on: pull_request_target
                permissions: write-all
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - run: echo ok
                """;
        List<RuleFinding> vuln = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/vuln5.yml", vulnYaml));
        assertTrue(hasFinding(vuln, "GG-CI-005"), "Should detect write-all permissions");

        String safeYaml = """
                name: Minimal Perms
                on: pull_request_target
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - run: echo ok
                """;
        List<RuleFinding> safe = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/safe5.yml", safeYaml));
        assertFalse(hasFinding(safe, "GG-CI-005"), "Explicit minimal permissions block is safe");
    }

    // GG-CI-006: Self-hosted runner
    @Test
    public void testRuleGgCi006PositiveAndNegative() {
        String vulnYaml = """
                name: Self Hosted Runner
                on: push
                permissions:
                  contents: read
                jobs:
                  build:
                    runs-on: self-hosted
                    steps:
                      - run: echo test
                """;
        List<RuleFinding> vuln = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/vuln6.yml", vulnYaml));
        assertTrue(hasFinding(vuln, "GG-CI-006"), "Should detect self-hosted runner");

        String safeYaml = """
                name: GitHub Hosted
                on: push
                permissions:
                  contents: read
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - run: echo test
                """;
        List<RuleFinding> safe = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/safe6.yml", safeYaml));
        assertFalse(hasFinding(safe, "GG-CI-006"), "ubuntu-latest runner is safe");
    }

    // GG-CI-007: ACTIONS_ALLOW_UNSECURE_COMMANDS
    @Test
    public void testRuleGgCi007PositiveAndNegative() {
        String vulnYaml = """
                name: Unsecure Commands
                on: push
                env:
                  ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - run: echo ok
                """;
        List<RuleFinding> vuln = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/vuln7.yml", vulnYaml));
        assertTrue(hasFinding(vuln, "GG-CI-007"), "Should detect ACTIONS_ALLOW_UNSECURE_COMMANDS");

        String safeYaml = """
                name: Modern Environment
                on: push
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - run: echo "FOO=bar" >> $GITHUB_ENV
                """;
        List<RuleFinding> safe = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/safe7.yml", safeYaml));
        assertFalse(hasFinding(safe, "GG-CI-007"), "GITHUB_ENV usage is safe");
    }

    // GG-CI-008: workflow_run artifact download
    @Test
    public void testRuleGgCi008PositiveAndNegative() {
        String vulnYaml = """
                name: Workflow Run Artifacts
                on:
                  workflow_run:
                    workflows: ["CI"]
                    types: [completed]
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/download-artifact@v4
                """;
        List<RuleFinding> vuln = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/vuln8.yml", vulnYaml));
        assertTrue(hasFinding(vuln, "GG-CI-008"), "Should detect artifact download in workflow_run");

        String safeYaml = """
                name: Push Artifacts
                on: push
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/download-artifact@v4
                """;
        List<RuleFinding> safe = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/safe8.yml", safeYaml));
        assertFalse(hasFinding(safe, "GG-CI-008"), "Push download-artifact is safe from GG-CI-008");
    }

    // GG-CI-009: actions/cache poisoning across trust boundaries
    @Test
    public void testRuleGgCi009PositiveAndNegative() {
        String vulnYaml = """
                name: PR Target Cache
                on: pull_request_target
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/cache@v4
                        with:
                          path: ~/.npm
                          key: ${{ runner.os }}-node
                """;
        List<RuleFinding> vuln = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/vuln9.yml", vulnYaml));
        assertTrue(hasFinding(vuln, "GG-CI-009"), "Should detect actions/cache under untrusted pull_request_target");

        String safeYaml = """
                name: Push Cache
                on: push
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/cache@v4
                        with:
                          path: ~/.npm
                          key: ${{ runner.os }}-node
                """;
        List<RuleFinding> safe = engine.scanWorkflow(new WorkflowFile("org/repo", ".github/workflows/safe9.yml", safeYaml));
        assertFalse(hasFinding(safe, "GG-CI-009"), "Cache under push is safe from GG-CI-009");
    }

    // GG-IAM-001: PassRole + compute creation
    @Test
    public void testRuleGgIam001PositiveAndNegative() {
        PolicyStatement passRole = new PolicyStatement("Allow", Set.of("iam:PassRole"), Set.of(), Set.of("*"), Set.of(), Map.of());
        PolicyStatement createCompute = new PolicyStatement("Allow", Set.of("lambda:CreateFunction"), Set.of(), Set.of("*"), Set.of(), Map.of());
        ParsedRole vulnRole = new ParsedRole("vuln-role", "arn:aws:iam::111111111111:role/vuln-role", false,
                new AwsIamService.OidcTrustInfo(false, "", List.of(), false, false, null),
                List.of(passRole, createCompute), Set.of(), Set.of());

        List<RuleFinding> vuln = engine.scanIam(new IamParseResult(Map.of("vuln-role", vulnRole), Map.of(), List.of()));
        assertTrue(hasFinding(vuln, "GG-IAM-001"), "Should detect PassRole + compute creation combination");

        PolicyStatement s3Only = new PolicyStatement("Allow", Set.of("s3:GetObject"), Set.of(), Set.of("*"), Set.of(), Map.of());
        ParsedRole safeRole = new ParsedRole("safe-role", "arn:aws:iam::111111111111:role/safe-role", false,
                new AwsIamService.OidcTrustInfo(false, "", List.of(), false, false, null),
                List.of(passRole, s3Only), Set.of(), Set.of());
        List<RuleFinding> safe = engine.scanIam(new IamParseResult(Map.of("safe-role", safeRole), Map.of(), List.of()));
        assertFalse(hasFinding(safe, "GG-IAM-001"), "PassRole without compute creation is safe from GG-IAM-001");
    }

    // GG-IAM-002: iam:* or *:* on Resource *
    @Test
    public void testRuleGgIam002PositiveAndNegative() {
        ParsedRole adminRole = new ParsedRole("admin-role", "arn:aws:iam::111111111111:role/admin-role", true,
                new AwsIamService.OidcTrustInfo(false, "", List.of(), false, false, null),
                List.of(), Set.of("AdministratorAccess"), Set.of());
        List<RuleFinding> vuln = engine.scanIam(new IamParseResult(Map.of("admin-role", adminRole), Map.of(), List.of()));
        assertTrue(hasFinding(vuln, "GG-IAM-002"), "Should detect full admin wildcard access");

        PolicyStatement scoped = new PolicyStatement("Allow", Set.of("s3:GetObject"), Set.of(), Set.of("arn:aws:s3:::my-bucket/*"), Set.of(), Map.of());
        ParsedRole scopedRole = new ParsedRole("scoped-role", "arn:aws:iam::111111111111:role/scoped-role", false,
                new AwsIamService.OidcTrustInfo(false, "", List.of(), false, false, null),
                List.of(scoped), Set.of(), Set.of());
        List<RuleFinding> safe = engine.scanIam(new IamParseResult(Map.of("scoped-role", scopedRole), Map.of(), List.of()));
        assertFalse(hasFinding(safe, "GG-IAM-002"), "Scoped role is safe from GG-IAM-002");
    }

    // GG-IAM-003: Over-broad OIDC trust
    @Test
    public void testRuleGgIam003PositiveAndNegative() {
        AwsIamService.OidcTrustInfo overbroad = new AwsIamService.OidcTrustInfo(true, "sts.amazonaws.com", List.of("repo:org/*"), false, true, "Wildcard repo");
        ParsedRole roleWithWildcard = new ParsedRole("oidc-role", "arn:aws:iam::111111111111:role/oidc-role", false,
                overbroad, List.of(), Set.of(), Set.of());
        List<RuleFinding> vuln = engine.scanIam(new IamParseResult(Map.of("oidc-role", roleWithWildcard), Map.of(), List.of()));
        assertTrue(hasFinding(vuln, "GG-IAM-003"), "Should detect overbroad OIDC trust");

        AwsIamService.OidcTrustInfo strict = new AwsIamService.OidcTrustInfo(true, "sts.amazonaws.com", List.of("repo:org/repo:ref:refs/heads/main"), false, false, null);
        ParsedRole strictRole = new ParsedRole("strict-role", "arn:aws:iam::111111111111:role/strict-role", false,
                strict, List.of(), Set.of(), Set.of());
        List<RuleFinding> safe = engine.scanIam(new IamParseResult(Map.of("strict-role", strictRole), Map.of(), List.of()));
        assertFalse(hasFinding(safe, "GG-IAM-003"), "Strict OIDC trust is safe from GG-IAM-003");
    }

    // Attack path risk score and severity
    @Test
    public void testPathRiskScoringAndFiltering() {
        AttackPath criticalPath = new AttackPath(
                "p-crit", 5,
                List.of("trg:1", "wf:1", "job:1", "role:deploy", "role:admin", "res:db"),
                List.of("pull_request_target", "deploy.yml", "deploy", "deploy-role", "admin-role", "customer-db"),
                List.of("Trigger", "Workflow", "Job", "Role", "Role", "Resource"),
                List.of("FIRES", "RUNS_JOB", "ASSUMES", "CAN_PASS_ROLE", "CAN_ACCESS"),
                List.of("expl1", "expl2", "expl3", "expl4", "expl5"),
                false, ""
        );

        AttackPath evaluated = engine.evaluatePathRisk(criticalPath);
        assertTrue(evaluated.riskScore() >= 8.5, "PR target to customer-db via PassRole should be critical risk");
        assertEquals("critical", evaluated.severity());
        assertNotNull(evaluated.riskReason());
        assertTrue(evaluated.riskReason().contains("Risk Score"));

        AttackPath mediumPath = new AttackPath(
                "p-med", 3,
                List.of("trg:2", "wf:2", "job:2", "sec:token"),
                List.of("push", "build.yml", "build", "BUILD_TOKEN"),
                List.of("Trigger", "Workflow", "Job", "Secret"),
                List.of("FIRES", "RUNS_JOB", "CAN_READ"),
                List.of("e1", "e2", "e3"),
                false, ""
        );
        AttackPath medEvaluated = engine.evaluatePathRisk(mediumPath);
        assertTrue(medEvaluated.riskScore() < evaluated.riskScore());

        // Test filtering
        List<AttackPath> filteredHigh = engine.scoreAndFilterPaths(List.of(criticalPath, mediumPath), "high", null);
        assertEquals(1, filteredHigh.size());
        assertEquals("p-crit", filteredHigh.get(0).key());

        List<AttackPath> filteredEntry = engine.scoreAndFilterPaths(List.of(criticalPath, mediumPath), null, "pull_request_target");
        assertEquals(1, filteredEntry.size());
        assertEquals("p-crit", filteredEntry.get(0).key());
    }

    // Patch generation
    @Test
    public void testGeneratePatch() {
        WorkflowFile wf = new WorkflowFile("org/repo", ".github/workflows/deploy.yml", "name: test\non: pull_request_target");
        RuleFinding finding = new RuleFinding("GG-CI-001", "critical", "PR Target issue", "desc", "remed", "target", "deploy.yml", ".github/workflows/deploy.yml", 1);
        PatchSuggestion patch = engine.generatePatch(finding, wf);
        assertNotNull(patch);
        assertEquals("GG-CI-001", patch.ruleId());
        assertTrue(patch.unifiedDiff().contains("pull_request"));
    }
}
