package com.graphguard;

import com.falkordb.Driver;
import com.falkordb.FalkorDB;
import com.graphguard.Models.AttackPath;
import com.graphguard.Models.Edge;
import com.graphguard.Models.SimResult;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class GraphGuardTest {
    private static GraphService graphs;
    private static Ingestor ingestor;
    private static AnalysisService analysis;
    private static AgentService agent;
    private static boolean falkorRunning;
    private static final String TEST_GRAPH = "test_graphguard";

    @BeforeAll
    public static void setUp() {
        falkorRunning = checkFalkor();
        if (falkorRunning) {
            Driver driver = FalkorDB.driver("localhost", 6379);
            graphs = new GraphService(driver, TEST_GRAPH);
            ingestor = new Ingestor(graphs, "");
            analysis = new AnalysisService(graphs, ingestor);
            agent = new AgentService(graphs, analysis, "", "claude-sonnet-5-5");
            ingestor.loadMain(ingestor.sampleSources());
        } else {
            graphs = Mockito.mock(GraphService.class);
            when(graphs.main()).thenReturn(TEST_GRAPH);
            ingestor = new Ingestor(graphs, "");
            ingestor.loadMain(ingestor.sampleSources());
            analysis = new AnalysisService(graphs, ingestor);
            agent = new AgentService(graphs, analysis, "", "claude-sonnet-5-5");
            setupMocks();
        }
    }

    @AfterAll
    public static void tearDown() {
        if (falkorRunning && graphs != null) {
            graphs.deleteGraph(TEST_GRAPH);
        }
    }

    private static boolean checkFalkor() {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("localhost", 6379), 400);
            Driver driver = FalkorDB.driver("localhost", 6379);
            driver.graph("test_check").query("MATCH (a), (b) CALL algo.SPpaths(a, b, 'FIRES') YIELD path RETURN path");
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static void setupMocks() {
        List<Map<String, Object>> mockAllNodes = List.of(
                Map.of("id", "trg:wf:demo-org/shop-web:.github/workflows/deploy.yml:pull_request_target", "name", "pull_request_target", "label", "Trigger"),
                Map.of("id", "wf:demo-org/shop-web:.github/workflows/deploy.yml", "name", "deploy.yml", "label", "Workflow"),
                Map.of("id", "job:wf:demo-org/shop-web:.github/workflows/deploy.yml:deploy", "name", "deploy", "label", "Job"),
                Map.of("id", "act:cool-org/cool-linter@v2", "name", "cool-org/cool-linter@v2", "label", "Action"),
                Map.of("id", "role:deployer", "name", "deployer", "label", "Role"),
                Map.of("id", "resource:customer-db", "name", "customer-db", "label", "Resource")
        );
        when(graphs.read(eq(TEST_GRAPH), org.mockito.ArgumentMatchers.contains("WHERE NOT 'Decision' IN labels(n) AND NOT 'Finding' IN labels(n)"), any())).thenReturn(mockAllNodes);

        List<Map<String, Object>> pathRows = List.of(
                Map.of(
                        "ids", List.of("trg:1", "wf:1", "job:1", "sec:1"),
                        "names", List.of("pull_request_target", "release.yml", "release", "PROD_API_KEY"),
                        "labels", List.of("Trigger", "Workflow", "Job", "Secret"),
                        "types", List.of("FIRES", "RUNS_JOB", "CAN_READ")
                ),
                Map.of(
                        "ids", List.of("trg:2", "wf:2", "job:2", "role:deployer", "role:admin", "res:db"),
                        "names", List.of("pull_request_target", "deploy.yml", "deploy", "deployer", "admin", "customer-db"),
                        "labels", List.of("Trigger", "Workflow", "Job", "Role", "Role", "Resource"),
                        "types", List.of("FIRES", "RUNS_JOB", "ASSUMES", "CAN_ASSUME", "CAN_ACCESS")
                ),
                Map.of(
                        "ids", List.of("trg:3", "wf:3", "job:3", "act:linter", "role:deployer", "role:admin", "res:db"),
                        "names", List.of("issue_comment", "labeler.yml", "label", "cool-linter", "deployer", "admin", "customer-db"),
                        "labels", List.of("Trigger", "Workflow", "Job", "Action", "Role", "Role", "Resource"),
                        "types", List.of("FIRES", "RUNS_JOB", "RUNS_IN", "ASSUMES", "CAN_ASSUME", "CAN_ACCESS")
                )
        );
        when(graphs.read(eq(TEST_GRAPH), org.mockito.ArgumentMatchers.contains("r.sensitive = true"), any())).thenReturn(pathRows);

        when(graphs.read(eq(TEST_GRAPH), org.mockito.ArgumentMatchers.contains("MATCH p = (s)-[*1..1]->(x)"), any())).thenReturn(List.of(
                Map.of("id", "job:1", "name", "deploy", "label", "Job", "sensitive", false, "via", List.of("cool-linter", "deploy"), "hops", 1)
        ));

        when(graphs.read(eq(TEST_GRAPH), org.mockito.ArgumentMatchers.contains("MATCH p = (s)-[*1..4]->(x)"), any())).thenReturn(List.of(
                Map.of("id", "job:1", "name", "deploy", "label", "Job", "sensitive", false, "via", List.of("cool-linter", "deploy"), "hops", 1),
                Map.of("id", "role:1", "name", "deployer", "label", "Role", "sensitive", false, "via", List.of("cool-linter", "deploy", "deployer"), "hops", 2),
                Map.of("id", "role:2", "name", "admin", "label", "Role", "sensitive", false, "via", List.of("cool-linter", "deploy", "deployer", "admin"), "hops", 3),
                Map.of("id", "res:1", "name", "customer-db", "label", "Resource", "sensitive", true, "via", List.of("cool-linter", "deploy", "deployer", "admin", "customer-db"), "hops", 4),
                Map.of("id", "res:1", "name", "customer-db", "label", "Resource", "sensitive", true, "via", List.of("cool-linter", "deploy", "deployer", "admin", "customer-db"), "hops", 5),
                Map.of("id", "node:5", "name", "lambda-fn", "label", "Resource", "sensitive", false, "via", List.of("cool-linter", "lambda"), "hops", 3),
                Map.of("id", "node:6", "name", "s3-bucket", "label", "Resource", "sensitive", false, "via", List.of("cool-linter", "s3"), "hops", 3),
                Map.of("id", "node:7", "name", "kms-key", "label", "Resource", "sensitive", false, "via", List.of("cool-linter", "kms"), "hops", 4)
        ));

        when(graphs.read(eq(TEST_GRAPH), org.mockito.ArgumentMatchers.contains("algo.pageRank"), any())).thenReturn(List.of(
                Map.of("id", "1", "name", "role:admin", "label", "Role", "score", 0.35),
                Map.of("id", "2", "name", "role:deployer", "label", "Role", "score", 0.25),
                Map.of("id", "3", "name", "deploy.yml", "label", "Workflow", "score", 0.18),
                Map.of("id", "4", "name", "customer-db", "label", "Resource", "score", 0.12),
                Map.of("id", "5", "name", "cool-linter", "label", "Action", "score", 0.10)
        ));

        when(graphs.read(eq(TEST_GRAPH), org.mockito.ArgumentMatchers.contains("algo.SPpaths"), any())).thenReturn(List.of(
                Map.of("ids", List.of("trg:1", "wf:1", "res:1"), "names", List.of("pull_request_target", "deploy.yml", "customer-db"),
                        "labels", List.of("Trigger", "Workflow", "Resource"), "types", List.of("FIRES", "CAN_ACCESS"), "hops", 2)
        ));

        when(graphs.read(eq(TEST_GRAPH), org.mockito.ArgumentMatchers.contains("MATCH (a {id:$s})-[r:"), any())).thenAnswer(inv -> {
            Map<?, ?> p = inv.getArgument(2);
            if (p != null && "role:demo-org/shop-web:deployer".equals(p.get("s"))) {
                return List.of(Map.of("c", 1L));
            }
            return List.of(Map.of("c", 0L));
        });

        when(graphs.read(eq(TEST_GRAPH), org.mockito.ArgumentMatchers.contains("MATCH (f:Finding)-[:ABOUT]->(n)"), any())).thenReturn(List.of(
                Map.of("id", "find:123", "text", "audit finding", "at", "2026-10-17T10:00:00Z", "type", "Finding", "nodeName", "cool-org/cool-linter@v2")
        ));
    }

    @Test
    @Order(1)
    public void test1SampleIngestAndAttackPaths() {
        List<AttackPath> paths = analysis.findPaths(graphs.main());
        assertEquals(3, paths.size());
        assertEquals(3, paths.get(0).length());
        assertEquals(5, paths.get(1).length());
        assertEquals(6, paths.get(2).length());
    }

    @Test
    @Order(2)
    public void test2BlastRadiusDepth1() {
        Map<String, Object> r = analysis.blastRadius(graphs.main(), "cool-org/cool-linter@v2", 1);
        assertEquals("answered_with_path", r.get("outcome"));
        assertEquals(1, r.get("reachableCount"));
    }

    @Test
    @Order(3)
    public void test3BlastRadiusDepth4() {
        Map<String, Object> r = analysis.blastRadius(graphs.main(), "cool-org/cool-linter@v2", 4);
        assertEquals("answered_with_path", r.get("outcome"));
        assertEquals(7, r.get("reachableCount"));
        @SuppressWarnings("unchecked")
        List<String> sens = (List<String>) r.get("sensitiveReached");
        assertTrue(sens.contains("customer-db"));
        long count = sens.stream().filter("customer-db"::equals).count();
        assertEquals(1, count);
    }

    @Test
    @Order(4)
    public void test4UnknownNodeBlastRadius() {
        Map<String, Object> r = analysis.blastRadius(graphs.main(), "payment-service", 4);
        assertEquals("unknown_node", r.get("outcome"));
        assertEquals(0, r.get("rows"));
        assertEquals(0, r.get("reachableCount"));
    }

    @Test
    @Order(5)
    public void test5LoadBearingPageRank() {
        Map<String, Object> r = analysis.loadBearing(graphs.main(), 5);
        @SuppressWarnings("unchecked")
        List<?> rows = (List<?>) r.get("rows");
        assertEquals(5, rows.size());
        String algo = String.valueOf(r.get("algorithm"));
        assertTrue(algo.toLowerCase().contains("pagerank"));
    }

    @Test
    @Order(6)
    public void test6PathBetween() {
        Map<String, Object> r = analysis.pathBetween(graphs.main(), "pull_request_target", "customer-db");
        assertEquals("answered_with_path", r.get("outcome"));
        assertTrue(((Number) r.get("hops")).intValue() > 0);
        @SuppressWarnings("unchecked")
        List<String> sentences = (List<String>) r.get("sentences");
        assertNotNull(sentences);
        assertFalse(sentences.isEmpty());
    }

    @Test
    @Order(7)
    public void test7SimulateFixExisting() {
        if (!falkorRunning) {
            when(graphs.read(eq(TEST_GRAPH), org.mockito.ArgumentMatchers.contains("MATCH (a {id:$s})-[r:"), any())).thenReturn(List.of(Map.of("c", 0L)));
        }
        SimResult r = analysis.simulate(new Edge("role:demo-org/shop-web:deployer", "CAN_ASSUME", "role:demo-org/shop-web:admin"));
        if (!falkorRunning) {
            assertNotNull(r);
            assertEquals("CAN_ASSUME", r.edge().type());
        } else {
            assertTrue(r.edgeExisted());
            assertTrue(r.after() < r.before());
        }
    }

    @Test
    @Order(8)
    public void test8SimulateFixNonExistingReturnsEarly() {
        SimResult r = analysis.simulate(new Edge("non-existent-source", "FIRES", "non-existent-target"));
        assertFalse(r.edgeExisted());
        assertEquals(r.before(), r.after());
    }

    @Test
    @Order(9)
    public void test9SaveFindingAndRecall() {
        Map<String, Object> saved = analysis.saveFinding(graphs.main(), "cool-org/cool-linter@v2", "Hardcoded credentials observed");
        assertEquals("memory", saved.get("outcome"));
        assertNotNull(saved.get("at"));

        Map<String, Object> recalled = analysis.recall(graphs.main(), "cool-org/cool-linter@v2");
        assertEquals("memory", recalled.get("outcome"));
        assertTrue(((Number) recalled.get("rows")).intValue() >= 1);
    }

    @Test
    @Order(10)
    public void test10AcceptRisk() {
        List<AttackPath> paths = analysis.findPaths(graphs.main());
        String key = paths.get(0).key();
        analysis.acceptRisk(graphs.main(), key, "sec-team", "accepted in Q4", 14);

        if (falkorRunning) {
            Map<String, Object> choke = analysis.chokePoints(graphs.main());
            assertTrue(((Number) choke.get("activePaths")).intValue() <= paths.size() - 1);
        }
    }

    @Test
    @Order(11)
    public void test11AgentAskUnknownNodeNoGuessedName() {
        Models.AgentAnswer answer = agent.ask("blast radius of payment-service");
        assertEquals("unknown_node", answer.outcome());
        assertFalse(answer.answer().toLowerCase().contains("admin"));
        assertFalse(answer.answer().toLowerCase().contains("customer-db"));
        assertTrue(answer.answer().contains("payment-service"));
        assertNotNull(answer.toolCalls());
        assertFalse(answer.toolCalls().isEmpty());
        assertEquals("unknown_node", answer.toolCalls().get(0).get("outcome"));
    }

    @Test
    @Order(12)
    public void test12IngestResetRelinksMemory() {
        if (falkorRunning) {
            analysis.saveFinding(graphs.main(), "cool-org/cool-linter@v2", "Finding to persist");
            ingestor.loadMain(ingestor.sampleSources());
            Map<String, Object> recalled = analysis.recall(graphs.main(), "cool-org/cool-linter@v2");
            assertEquals("memory", recalled.get("outcome"));
            assertTrue(((Number) recalled.get("rows")).intValue() >= 1);
        }
    }

    @Test
    @Order(13)
    public void test13PathCacheServedFromCacheAndIdentical() {
        analysis.invalidatePathCache();
        assertFalse(analysis.isPathCachePopulated(), "Cache should be empty initially");

        List<AttackPath> uncached = analysis.findPaths(graphs.main());
        assertTrue(analysis.isPathCachePopulated(), "Cache should be populated after first findPaths on main");

        List<AttackPath> cached = analysis.findPaths(graphs.main());
        assertEquals(uncached.size(), cached.size(), "Cached paths count should match uncached");
        for (int i = 0; i < uncached.size(); i++) {
            assertEquals(uncached.get(i).key(), cached.get(i).key());
            assertEquals(uncached.get(i).length(), cached.get(i).length());
            assertEquals(uncached.get(i).riskScore(), cached.get(i).riskScore());
            assertEquals(uncached.get(i).severity(), cached.get(i).severity());
        }

        // Verify sim graphs never populate or touch main cache
        analysis.invalidatePathCache();
        analysis.findPaths("sim_test123");
        assertFalse(analysis.isPathCachePopulated(), "Cache should never be populated for sim_ graphs");
    }

    @Test
    @Order(14)
    public void test14PathCacheClearedAfterIngestAndLoadIam() {
        analysis.findPaths(graphs.main());
        assertTrue(analysis.isPathCachePopulated(), "Cache should be populated");

        ingestor.loadMain(ingestor.sampleSources());
        assertFalse(analysis.isPathCachePopulated(), "Cache should be cleared after loadMain");

        analysis.findPaths(graphs.main());
        assertTrue(analysis.isPathCachePopulated(), "Cache should be re-populated");

        ingestor.loadIam(ingestor.sampleSources().iamJson());
        assertFalse(analysis.isPathCachePopulated(), "Cache should be cleared after loadIam");
    }

    @Test
    @Order(15)
    public void test15PathCacheClearedAfterAcceptRisk() {
        List<AttackPath> paths = analysis.findPaths(graphs.main());
        assertTrue(analysis.isPathCachePopulated(), "Cache should be populated");
        String key = paths.get(0).key();

        analysis.acceptRisk(graphs.main(), key, "qa-team", "accepted risk for test", 30);
        assertFalse(analysis.isPathCachePopulated(), "Cache should be cleared after acceptRisk");
    }

    @Test
    @Order(16)
    public void test16DefensiveCopyPreventsCacheMutation() {
        List<AttackPath> p1 = analysis.findPaths(graphs.main());
        int originalSize = p1.size();
        assertTrue(originalSize > 0);

        // Caller modifies the returned list
        p1.clear();
        assertEquals(0, p1.size());

        // Cache must remain untouched
        List<AttackPath> p2 = analysis.findPaths(graphs.main());
        assertEquals(originalSize, p2.size(), "Cached list must not be affected by caller mutating returned copy");
    }

    @Test
    @Order(17)
    public void test17PathQueryContainsEdgeTypeWhitelistAndDepth8() {
        assertTrue(AnalysisService.PATH_QUERY.contains("*1..8"));
        assertTrue(AnalysisService.PATH_QUERY.contains("FIRES"));
        assertTrue(AnalysisService.PATH_QUERY.contains("ASSUMES"));
        assertTrue(AnalysisService.PATH_QUERY.contains("CAN_READ"));
        assertEquals(AnalysisService.EDGE_TYPES, GraphService.EDGE_TYPES);
        assertEquals(AnalysisService.PATH_QUERY, GraphService.PATH_QUERY);
    }
}
