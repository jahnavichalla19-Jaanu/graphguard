package com.graphguard;

import com.graphguard.Models.SourceSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

public class GithubSourcesTest {

    private GraphService mockGraphs;
    private AwsIamService mockIam;

    @BeforeEach
    void setUp() {
        mockGraphs = Mockito.mock(GraphService.class);
        mockIam = Mockito.mock(AwsIamService.class);
    }

    @Test
    void testValidateGithubHostRestrictedToApiGithubCom() {
        Ingestor ingestor = new Ingestor(mockGraphs, mockIam, "");

        // api.github.com is permitted
        ingestor.validateGithubHost(URI.create("https://api.github.com/repos/org/repo/contents/.github/workflows"));

        // raw.githubusercontent.com is blocked
        SecurityException e1 = assertThrows(SecurityException.class, () ->
                ingestor.validateGithubHost(URI.create("https://raw.githubusercontent.com/org/repo/main/.github/workflows/deploy.yml")));
        assertTrue(e1.getMessage().contains("SSRF blocked"));

        // other hosts are blocked
        SecurityException e2 = assertThrows(SecurityException.class, () ->
                ingestor.validateGithubHost(URI.create("https://attacker.com/evil")));
        assertTrue(e2.getMessage().contains("SSRF blocked"));
    }

    @Test
    void testGithubSourcesUsesUrlFieldAndRawHeader() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        RestClient client = builder.build();

        Ingestor ingestor = new Ingestor(mockGraphs, mockIam, "test-token", client);

        String listingJson = """
                [
                  {
                    "name": "ci.yml",
                    "url": "https://api.github.com/repos/test-org/test-repo/contents/.github/workflows/ci.yml?ref=main",
                    "download_url": "https://raw.githubusercontent.com/test-org/test-repo/main/.github/workflows/ci.yml"
                  }
                ]
                """;

        String workflowContent = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n";

        // Directory listing expectation: uses Accept application/vnd.github+json
        server.expect(requestTo("https://api.github.com/repos/test-org/test-repo/contents/.github/workflows"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Accept", "application/vnd.github+json"))
                .andExpect(header("Authorization", "Bearer test-token"))
                .andRespond(withSuccess(listingJson, MediaType.APPLICATION_JSON));

        // File download expectation: uses url field from listing and Accept application/vnd.github.raw
        server.expect(requestTo("https://api.github.com/repos/test-org/test-repo/contents/.github/workflows/ci.yml?ref=main"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Accept", "application/vnd.github.raw"))
                .andExpect(header("Authorization", "Bearer test-token"))
                .andRespond(withSuccess(workflowContent, MediaType.TEXT_PLAIN));

        SourceSet result = ingestor.githubSources("test-org", "test-repo");
        assertNotNull(result);
        assertEquals(1, result.workflows().size());
        assertEquals(".github/workflows/ci.yml", result.workflows().get(0).path());
        assertEquals(workflowContent, result.workflows().get(0).yaml());

        server.verify();
    }

    @Test
    void testGithubSourcesFailureReportsRealExceptionClassAndMessage() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        RestClient client = builder.build();

        Ingestor ingestor = new Ingestor(mockGraphs, mockIam, "", client);

        server.expect(requestTo("https://api.github.com/repos/test-org/fail-repo/contents/.github/workflows"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                ingestor.githubSources("test-org", "fail-repo"));

        // Must report real exception class name and message, NOT the generic text
        assertTrue(ex.getMessage().contains("HttpServerErrorException") || ex.getMessage().contains("500"),
                "Message should include real exception/status: " + ex.getMessage());
        assertFalse(ex.getMessage().contains("private repo, no workflows, or rate limit"),
                "Message should not contain generic text: " + ex.getMessage());
    }
}
