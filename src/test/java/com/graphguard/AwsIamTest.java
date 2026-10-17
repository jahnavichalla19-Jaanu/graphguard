package com.graphguard;

import com.graphguard.AwsIamService.IamParseResult;
import com.graphguard.AwsIamService.ParsedResource;
import com.graphguard.AwsIamService.ParsedRole;
import com.graphguard.AwsIamService.PolicyStatement;
import com.graphguard.Models.SourceSet;
import com.graphguard.Models.WorkflowFile;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

public class AwsIamTest {
    private final AwsIamService iamService = new AwsIamService();

    @Test
    public void testParseAuthorizationDetailsFixture() throws IOException {
        String json = new ClassPathResource("aws/account-authorization-details.json").getContentAsString(StandardCharsets.UTF_8);
        assertTrue(iamService.isAwsAuthDetails(json));

        IamParseResult result = iamService.parseAuthorizationDetails(json);
        assertNotNull(result);
        assertNotNull(result.roles());
        assertTrue(result.roles().containsKey("deploy-role"));
        assertTrue(result.roles().containsKey("admin-role"));
        assertTrue(result.roles().containsKey("readonly-role"));
        assertTrue(result.roles().containsKey("overbroad-oidc-role"));

        ParsedRole admin = result.roles().get("admin-role");
        assertTrue(admin.isAdmin(), "admin-role should be admin via AdministratorAccess");

        ParsedRole overbroad = result.roles().get("overbroad-oidc-role");
        assertTrue(overbroad.isAdmin(), "overbroad role should be admin via wildcard statement");
        assertTrue(overbroad.oidcTrust().overPermissive(), "overbroad OIDC trust should be flagged");

        ParsedRole deploy = result.roles().get("deploy-role");
        assertFalse(deploy.isAdmin());
        assertTrue(deploy.oidcTrust().trustsGithub());
        assertFalse(deploy.oidcTrust().overPermissive());
    }

    @Test
    public void testOidcMatchAndNoMatch() throws IOException {
        String json = new ClassPathResource("aws/account-authorization-details.json").getContentAsString(StandardCharsets.UTF_8);
        IamParseResult result = iamService.parseAuthorizationDetails(json);

        ParsedRole deploy = result.roles().get("deploy-role");
        ParsedRole readonly = result.roles().get("readonly-role");

        // deploy-role trusts repo:demo-org/shop-web:pull_request
        assertTrue(iamService.matchesOidc(deploy.oidcTrust(), "demo-org/shop-web", Set.of("pull_request_target"), null));
        assertTrue(iamService.matchesOidc(deploy.oidcTrust(), "demo-org/shop-web", Set.of("pull_request"), null));

        // readonly-role trusts repo:demo-org/shop-web:ref:refs/heads/main
        assertFalse(iamService.matchesOidc(readonly.oidcTrust(), "demo-org/shop-web", Set.of("pull_request_target"), null));
        assertTrue(iamService.matchesOidc(readonly.oidcTrust(), "demo-org/shop-web", Set.of("push"), "main"));

        // Different repo should not match
        assertFalse(iamService.matchesOidc(deploy.oidcTrust(), "attacker-org/evil-repo", Set.of("pull_request_target"), null));
    }

    @Test
    public void testWildcardAndDenyHandling() {
        // Wildcard glob testing
        assertTrue(AwsIamService.glob("s3:*", "s3:GetObject"));
        assertTrue(AwsIamService.glob("s3:*", "s3:PutObject"));
        assertFalse(AwsIamService.glob("s3:*", "rds:DescribeDBInstances"));
        assertTrue(AwsIamService.glob("arn:aws:s3:::build-*", "arn:aws:s3:::build-artifacts"));
        assertTrue(AwsIamService.glob("*", "anything"));

        // Deny overrides Allow
        PolicyStatement allowStmt = new PolicyStatement("Allow", Set.of("s3:*"), Set.of(), Set.of("arn:aws:s3:::my-bucket/*"), Set.of(), Map.of());
        PolicyStatement denyStmt = new PolicyStatement("Deny", Set.of("s3:DeleteObject"), Set.of(), Set.of("arn:aws:s3:::my-bucket/*"), Set.of(), Map.of());

        List<PolicyStatement> policy = List.of(allowStmt, denyStmt);
        assertTrue(iamService.checkPermission(policy, "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt"));
        assertFalse(iamService.checkPermission(policy, "s3:DeleteObject", "arn:aws:s3:::my-bucket/file.txt"), "Deny statement must override allow");
    }

    @Test
    public void testParseResourceArn() {
        ParsedResource rds = iamService.parseResourceArn("arn:aws:rds:us-east-1:111111111111:db:customer-db");
        assertNotNull(rds);
        assertEquals("customer-db", rds.name());
        assertEquals("rds", rds.type());
        assertTrue(rds.sensitive());

        ParsedResource s3 = iamService.parseResourceArn("arn:aws:s3:::build-artifacts/*");
        assertNotNull(s3);
        assertEquals("build-artifacts", s3.name());
        assertEquals("s3", s3.type());

        ParsedResource lambda = iamService.parseResourceArn("arn:aws:lambda:us-east-1:111111111111:function:billing-lambda");
        assertNotNull(lambda);
        assertEquals("billing-lambda", lambda.name());
        assertEquals("lambda", lambda.type());
        assertTrue(lambda.sensitive());
    }

    @Test
    public void testIngestorOidcPruningAndUnmatchedRoleWarning() throws IOException {
        GraphService mockGraphs = Mockito.mock(GraphService.class);
        when(mockGraphs.main()).thenReturn("test_graph");

        Ingestor ingestor = new Ingestor(mockGraphs, iamService, "");
        String iamJson = new ClassPathResource("aws/account-authorization-details.json").getContentAsString(StandardCharsets.UTF_8);

        // Workflow 1: pull_request_target attempts to assume readonly-role (which only allows main branch)
        // Workflow 2: push attempts to assume an unknown role
        String wfPr = """
                name: PR Workflow
                on: pull_request_target
                jobs:
                  job1:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: aws-actions/configure-aws-credentials@v4
                        with:
                          role-to-assume: arn:aws:iam::111111111111:role/readonly-role
                """;

        String wfUnknown = """
                name: Unknown Role Workflow
                on: push
                jobs:
                  job2:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: aws-actions/configure-aws-credentials@v4
                        with:
                          role-to-assume: arn:aws:iam::111111111111:role/nonexistent-role
                """;

        List<WorkflowFile> files = List.of(
                new WorkflowFile("demo-org/shop-web", ".github/workflows/pr.yml", wfPr),
                new WorkflowFile("demo-org/shop-web", ".github/workflows/unknown.yml", wfUnknown)
        );

        ingestor.loadMain(new SourceSet(files, iamJson));

        // Verify OIDC pruned path count
        assertTrue(ingestor.lastPrunedPaths() >= 1, "Should have pruned ASSUMES edge due to OIDC mismatch");

        // Verify unmatched role warning
        boolean hasWarning = ingestor.lastWarnings().stream().anyMatch(w -> w.contains("nonexistent-role"));
        assertTrue(hasWarning, "Should record warning for unmatched role");
    }
}
