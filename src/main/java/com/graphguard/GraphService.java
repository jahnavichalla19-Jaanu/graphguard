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

@Service
public class GraphService {
    private final Driver driver;
    private final String mainGraph;

    public GraphService(Driver driver, @Value("${falkordb.graph}") String mainGraph) {
        this.driver = driver;
        this.mainGraph = mainGraph;
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
    }

    public void deleteGraph(String graph) {
        try {
            driver.graph(graph).deleteGraph();
        } catch (Exception ignored) {
        }
    }
}