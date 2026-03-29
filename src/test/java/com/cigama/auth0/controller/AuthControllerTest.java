package com.cigama.auth0.controller;

import com.cigama.auth0.dto.request.LoginRequest;
import com.cigama.auth0.dto.request.RegisterRequest;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    // --- Variables ---

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    private ObjectMapper objectMapper;

    private RegisterRequest registerRequest;
    private final String apiKey = "test-api-key";

    @BeforeEach
    void setUp() {
        objectMapper = new com.fasterxml.jackson.databind.ObjectMapper();
        objectMapper.findAndRegisterModules();
        registerRequest = new RegisterRequest();
        registerRequest.setEmail("test@example.com");
        registerRequest.setUsername("testuser");
        registerRequest.setPassword("Password123");
        registerRequest.setConfirmPassword("Password123");
        registerRequest.setFirstName("John");
        registerRequest.setLastName("Doe");
        registerRequest.setPhoneNumber("0123456789");
    }

    // --- Test Cases ---

    @Test
    void register_WithValidRequest_ReturnsCreated() throws Exception {
        doNothing().when(authService).register(any(RegisterRequest.class), eq(apiKey));

        mockMvc.perform(post("/api/auth/register")
                        .header("X-API-Key", apiKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value(HttpStatus.CREATED.value()))
                .andExpect(jsonPath("$.message").value("User registered successfully"));
    }

    @Test
    void login_WithValidRequest_ReturnsToken() throws Exception {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmailOrUsername("testuser");
        loginRequest.setPassword("Password123");
        loginRequest.setClientName("TestClient");

        TokenResponse tokenResponse = TokenResponse.builder()
                .accessToken("access-token")
                .refreshToken("refresh-token")
                .tokenType("Bearer")
                .expiredIn(3600L)
                .build();

        when(authService.login(any(LoginRequest.class), eq(apiKey)))
                .thenReturn(tokenResponse);

        mockMvc.perform(post("/api/auth/login")
                        .header("X-API-Key", apiKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").value("access-token"))
                .andExpect(jsonPath("$.data.refreshToken").value("refresh-token"));
    }

    @Test
    void refresh_WithValidToken_ReturnsNewToken() throws Exception {
        Map<String, String> refreshRequest = new HashMap<>();
        refreshRequest.put("refreshToken", "valid-refresh-token");

        TokenResponse tokenResponse = TokenResponse.builder()
                .accessToken("new-access-token")
                .refreshToken("new-refresh-token")
                .tokenType("Bearer")
                .expiredIn(3600L)
                .build();

        when(authService.refresh("valid-refresh-token"))
                .thenReturn(tokenResponse);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").value("new-access-token"))
                .andExpect(jsonPath("$.data.refreshToken").value("new-refresh-token"));
    }
}
