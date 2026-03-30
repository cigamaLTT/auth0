package com.cigama.auth0.security;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class JwtAuthenticationEntryPointTest {

    // --- Variables ---

    private JwtAuthenticationEntryPoint entryPoint;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private ObjectMapper objectMapper;

    // --- Setup ---

    @BeforeEach
    void setUp() {
        entryPoint = new JwtAuthenticationEntryPoint();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        objectMapper = new ObjectMapper();
    }

    // --- Tests ---

    @Test
    void commence_WithJwtExceptionAttributes_ReturnsCustomError() throws ServletException, IOException {
        request.setAttribute("jwtExceptionType", "EXPIRED");
        request.setAttribute("jwtExceptionMessage", "Token has expired");

        AuthenticationException mockAuthException = new InsufficientAuthenticationException("Should be overridden by attributes");

        entryPoint.commence(request, response, mockAuthException);

        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatus());
        assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());

        JsonNode jsonResponse = objectMapper.readTree(response.getContentAsString());

        assertEquals(401, jsonResponse.get("status").asInt());
        assertEquals("Unauthorized", jsonResponse.get("error").asText());
        assertEquals("Token has expired", jsonResponse.get("message").asText());
        assertEquals("EXPIRED", jsonResponse.get("type").asText());
        assertTrueNodeIsNull(jsonResponse.get("data"));
    }

    @Test
    void commence_WithGeneralAuthenticationException_ReturnsFallbackError() throws ServletException, IOException {
        AuthenticationException mockAuthException = new InsufficientAuthenticationException("Full authentication is required to access this resource");

        entryPoint.commence(request, response, mockAuthException);

        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatus());

        JsonNode jsonResponse = objectMapper.readTree(response.getContentAsString());

        assertEquals(401, jsonResponse.get("status").asInt());
        assertEquals("Unauthorized", jsonResponse.get("error").asText());
        assertEquals("Full authentication is required to access this resource", jsonResponse.get("message").asText());
        assertEquals("AUTHENTICATION_FAILED", jsonResponse.get("type").asText());
    }

    @Test
    void commence_WithNullAuthExceptionMessage_ReturnsDefaultError() throws ServletException, IOException {
        AuthenticationException mockAuthException = new InsufficientAuthenticationException(null);

        entryPoint.commence(request, response, mockAuthException);

        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatus());

        JsonNode jsonResponse = objectMapper.readTree(response.getContentAsString());

        assertEquals(401, jsonResponse.get("status").asInt());
        assertEquals("Unauthorized", jsonResponse.get("error").asText());
        assertEquals("Unauthorized", jsonResponse.get("message").asText());
        assertEquals("AUTHENTICATION_FAILED", jsonResponse.get("type").asText());
    }

    @Test
    void commence_WithNullAuthException_ReturnsDefaultError() throws ServletException, IOException {
        entryPoint.commence(request, response, null);

        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatus());

        JsonNode jsonResponse = objectMapper.readTree(response.getContentAsString());

        assertEquals(401, jsonResponse.get("status").asInt());
        assertEquals("Unauthorized", jsonResponse.get("message").asText());
        assertEquals("AUTHENTICATION_FAILED", jsonResponse.get("type").asText());
    }

    // --- Private Helpers ---

    private void assertTrueNodeIsNull(JsonNode node) {
        if (node == null || node.isNull()) {
            assertNull(null);
        } else {
            assertEquals("null", node.asText());
        }
    }
}