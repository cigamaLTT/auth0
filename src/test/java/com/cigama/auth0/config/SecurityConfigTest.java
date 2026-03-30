package com.cigama.auth0.config;

import com.cigama.auth0.security.JwtAuthenticationEntryPoint;
import com.cigama.auth0.security.JwtAuthenticationFilter;
import com.cigama.auth0.security.JwtTokenProvider;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = {
        SecurityConfig.class,
        JwtAuthenticationFilter.class,
        SecurityConfigTest.DummyController.class
})
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "app.cors.allowed-origins=http://test-cors.com"
})
class SecurityConfigTest {

    // --- Variables ---

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtTokenProvider jwtTokenProvider;

    @MockitoBean
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @MockitoBean
    private tools.jackson.databind.ObjectMapper objectMapper;

    @MockitoBean
    private com.cigama.auth0.mapper.UserMapper userMapper;

    // --- Dummy Controller for Testing ---

    @RestController
    public static class DummyController {
        @GetMapping("/api/auth/ping")
        public String publicPing() {
            return "public-success";
        }

        @GetMapping("/api/secured/ping")
        public String securedPing() {
            return "secured-success";
        }
    }

    // --- Setup ---

    @BeforeEach
    void setUp() throws Exception {
        doAnswer(invocation -> {
            HttpServletResponse response = invocation.getArgument(1);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
            return null;
        }).when(jwtAuthenticationEntryPoint).commence(any(), any(), any());
    }

    // --- Tests ---

    @Test
    void securityFilterChain_PublicApi_ShouldAllowAccess() throws Exception {
        mockMvc.perform(get("/api/auth/ping"))
                .andExpect(status().isOk())
                .andExpect(content().string("public-success"));

        verify(jwtAuthenticationEntryPoint, never()).commence(any(), any(), any());
    }

    @Test
    void securityFilterChain_SecuredApiWithoutToken_ShouldBlockAndTriggerEntryPoint() throws Exception {
        mockMvc.perform(get("/api/secured/ping"))
                .andExpect(status().isUnauthorized());

        verify(jwtAuthenticationEntryPoint, times(1)).commence(any(), any(), any());
    }

    @Test
    void corsConfigurationSource_ValidOrigin_ShouldAllowCors() throws Exception {
        mockMvc.perform(options("/api/auth/ping")
                        .header("Origin", "http://test-cors.com")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://test-cors.com"))
                .andExpect(header().exists("Access-Control-Allow-Methods"))
                .andExpect(header().exists("Access-Control-Allow-Credentials"));
    }

    @Test
    void corsConfigurationSource_InvalidOrigin_ShouldRejectCors() throws Exception {
        mockMvc.perform(options("/api/auth/ping")
                        .header("Origin", "http://hacker-domain.com")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }
}