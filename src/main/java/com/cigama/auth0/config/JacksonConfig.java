package com.cigama.auth0.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import tools.jackson.databind.ObjectMapper;

@Configuration
public class JacksonConfig {

    // --- Beans ---

    /**
     * Provides a Jackson 3 ObjectMapper bean as requested for "fancy" features.
     * Used for manual serialization in Services, JWT, and Listeners.
     */
    @Bean
    public ObjectMapper toolsObjectMapper() {
        return new ObjectMapper();
    }

    /**
     * Keeps the standard Jackson 2 ObjectMapper available for Spring Boot's internal usage
     * (e.g., API requests/responses) to ensure compatibility.
     */
    @Bean
    public com.fasterxml.jackson.databind.ObjectMapper fastxmlObjectMapper() {
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        mapper.registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());
        return mapper;
    }
}
