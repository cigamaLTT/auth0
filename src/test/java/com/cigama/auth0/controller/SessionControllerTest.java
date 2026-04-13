package com.cigama.auth0.controller;

import com.cigama.auth0.dto.response.SessionResponse;
import com.cigama.auth0.dto.userdetails.CustomUserDetails;
import com.cigama.auth0.service.SessionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SessionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SessionService sessionService;

    private ObjectMapper objectMapper;
    private CustomUserDetails userDetails;
    private final UUID userId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        userDetails = CustomUserDetails.builder()
                .userId(userId.toString())
                .username("testuser")
                .role("ROLE_USER")
                .enabled(true)
                .build();

        // Mock the security context
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    @Test
    void getSessions_ReturnsList() throws Exception {
        SessionResponse session = SessionResponse.builder()
                .deviceId(UUID.randomUUID())
                .deviceName("Test Device")
                .ipAddress("127.0.0.1")
                .createdAt(LocalDateTime.now())
                .build();

        when(sessionService.getSessions(userId)).thenReturn(List.of(session));

        mockMvc.perform(get("/api/sessions")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].deviceName").value("Test Device"))
                .andExpect(jsonPath("$.data[0].ipAddress").value("127.0.0.1"));
    }

    @Test
    void revokeSession_WithValidId_ReturnsOk() throws Exception {
        UUID deviceId = UUID.randomUUID();
        doNothing().when(sessionService).revokeSession(eq(userId), eq(deviceId));

        mockMvc.perform(delete("/api/sessions/" + deviceId)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Session revoked successfully"));

        verify(sessionService, times(1)).revokeSession(eq(userId), eq(deviceId));
    }
}
