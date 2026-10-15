package com.graphguard;

import com.falkordb.Driver;
import com.falkordb.FalkorDB;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FalkorConfig {
    @Bean
    public Driver falkorDriver(@Value("${falkordb.host}") String host, @Value("${falkordb.port}") int port) {
        return FalkorDB.driver(host, port);
    }
}