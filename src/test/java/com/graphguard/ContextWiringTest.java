package com.graphguard;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

public class ContextWiringTest {

    @Test
    void testSpringBeansWireUpSuccessfully() {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();

        // Register mocked GraphService
        GraphService mockGraphService = Mockito.mock(GraphService.class);
        when(mockGraphService.main()).thenReturn("test_graphguard");
        context.getBeanFactory().registerSingleton("graphService", mockGraphService);

        // Supply properties required by @Value annotations
        context.getEnvironment().getPropertySources().addFirst(
                new MapPropertySource("testEnv", Map.of(
                        "falkordb.graph", "test_graphguard",
                        "anthropic.model", "claude-sonnet-5-5",
                        "anthropic.api-key", "",
                        "github.token", "",
                        "graphguard.aws.live", "false"
                ))
        );

        // Register application services and controller
        context.register(
                AwsIamService.class,
                DetectionEngine.class,
                Ingestor.class,
                AnalysisService.class,
                AgentService.class,
                ApiController.class
        );

        context.refresh();

        try {
            AnalysisService analysisService = context.getBean(AnalysisService.class);
            assertNotNull(analysisService, "AnalysisService should be instantiated and wired");

            Ingestor ingestor = context.getBean(Ingestor.class);
            assertNotNull(ingestor, "Ingestor should be instantiated and wired");

            AgentService agentService = context.getBean(AgentService.class);
            assertNotNull(agentService, "AgentService should be instantiated and wired");

            DetectionEngine detectionEngine = context.getBean(DetectionEngine.class);
            assertNotNull(detectionEngine, "DetectionEngine should be instantiated and wired");

            AwsIamService awsIamService = context.getBean(AwsIamService.class);
            assertNotNull(awsIamService, "AwsIamService should be instantiated and wired");

            ApiController apiController = context.getBean(ApiController.class);
            assertNotNull(apiController, "ApiController should be instantiated and wired");
        } finally {
            context.close();
        }
    }
}
