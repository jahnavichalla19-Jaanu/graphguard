package com.graphguard;

import com.falkordb.Driver;
import com.falkordb.Graph;
import com.falkordb.Record;
import com.falkordb.ResultSet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

@Service
public class GraphService {
    public static final Set<String> EDGE_TYPES = AnalysisService.EDGE_TYPES;
    public static final String PATH_QUERY = AnalysisService.PATH_QUERY;

    private final Driver driver;
    private final String mainGraph;
    private final List<Consumer<String>> writeListeners = new CopyOnWriteArrayList<>();

    public GraphService(Driver driver, @Value("${falkordb.graph}") String mainGraph) {
        this.driver = driver;
        this.mainGraph = mainGraph;
    }

    public void onWrite(Consumer<String> listener) {
        if (listener != null) {
            writeListeners.add(listener);
        }
    }

    public String main() {
        return mainGraph;
    }

    public List<Map<String, Object>> read(String graph, String cypher, Map<String, Object> params) {
        try {
            Graph g = driver.graph(graph);
            ResultSet rs = (params == null || params.isEmpty()) ? g.readOnlyQuery(cypher) : g.readOnlyQuery(cypher, params);
            List<Map<String, Object>> rows = new ArrayList<>();
            for (Record r : rs) {
                Map<String, Object> row = new LinkedHashMap<>();
                for (String key : r.keys()) {
                    row.put(key, r.getValue(key));
                }
                rows.add(row);
            }
            return rows;
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().toLowerCase().contains("empty key")) {
                return List.of();
            }
            if (e instanceof RuntimeException re) {
                throw re;
            }
            throw new RuntimeException(e);
        }
    }

    public List<Map<String, Object>> query(String graph, String cypher, Map<String, Object> params) {
        Graph g = driver.graph(graph);
        ResultSet rs = (params == null || params.isEmpty()) ? g.query(cypher) : g.query(cypher, params);
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Record r : rs) {
            Map<String, Object> row = new LinkedHashMap<>();
            for (String key : r.keys()) {
                row.put(key, r.getValue(key));
            }
            rows.add(row);
        }
        return rows;
    }

    public void write(String graph, String cypher, Map<String, Object> params) {
        query(graph, cypher, params);
        for (Consumer<String> listener : writeListeners) {
            try {
                listener.accept(graph);
            } catch (Exception ignored) {
            }
        }
    }

    public void deleteGraph(String graph) {
        try {
            driver.graph(graph).deleteGraph();
        } catch (Exception ignored) {
        }
    }
}