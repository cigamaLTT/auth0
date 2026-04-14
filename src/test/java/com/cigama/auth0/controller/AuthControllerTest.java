package com.cigama.auth0.controller;

import com.cigama.auth0.controller.doc.AuthApi;
import com.cigama.auth0.dto.request.*;
import com.cigama.auth0.dto.response.BaseResponse;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.dto.response.VerifyOtpResponse;
import com.cigama.auth0.service.AuthService;
import com.cigama.auth0.service.SessionService;
import com.cigama.auth0.service.ValidationService;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import java.util.Collections;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import com.cigama.auth0.dto.JwtPayload;
import com.cigama.auth0.dto.userdetails.CustomUserDetails;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    // --- Fields ---

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private ValidationService validationService;

    @MockitoBean
    private SessionService sessionService;

    private ObjectMapper objectMapper;

    private RegisterRequest registerRequest;
    private final String apiKey = "test-api-key";

    // --- Setup ---

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        registerRequest = new RegisterRequest(
                "test@example.com",
                "0123456789",
                "Password123",
                "Password123",
                "John",
                "Doe",
                "testuser",
                null
        );
    }

    // --- Test Cases ---

    @Test
    void register_WithValidRequest_ReturnsOk() throws Exception {
        doNothing().when(authService).register(any(RegisterRequest.class), eq(apiKey));

        mockMvc.perform(post("/api/auth/register")
                        .header("X-API-Key", apiKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(HttpStatus.OK.value()))
                .andExpect(jsonPath("$.message").value("OTP sent to your email"));
    }

    @Test
    void login_WithValidRequest_ReturnsToken() throws Exception {
        LoginRequest loginRequest = new LoginRequest(
                "testuser",
                "Password123",
                UUID.randomUUID(),
                "test-device"
        );

        TokenResponse tokenResponse = new TokenResponse("access-token", "refresh-token", "Bearer", 3600L);

        when(authService.login(any(LoginRequest.class), eq(apiKey), any(ClientMetadata.class)))
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
        RefreshTokenRequest refreshRequest = new RefreshTokenRequest("valid-refresh-token");

        TokenResponse tokenResponse = new TokenResponse("new-access-token", "new-refresh-token", "Bearer", 3600L);

        when(authService.refresh(eq("valid-refresh-token"), any(ClientMetadata.class)))
                .thenReturn(tokenResponse);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").value("new-access-token"))
                .andExpect(jsonPath("$.data.refreshToken").value("new-refresh-token"));
    }

    @Test
    void logout_WithValidHeader_ReturnsOk() throws Exception {
        doNothing().when(authService).logout(anyString());

        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer valid-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out successfully"));
    }

    @Test
    void changePassword_WithValidRequest_ReturnsOk() throws Exception {
        UUID userId = UUID.randomUUID();
        ChangePasswordRequest request = new ChangePasswordRequest("oldPass", "NewPass123", "NewPass123", false);
        CustomUserDetails userDetails = CustomUserDetails.builder()
                .userId(userId.toString())
                .username("testuser")
                .role("ROLE_USER")
                .enabled(true)
                .build();

        doNothing().when(authService).changePassword(eq(userId), any(ChangePasswordRequest.class));

        mockMvc.perform(post("/api/auth/change-password")
                        .with(authentication(new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities())))
                        .requestAttr("userId", userId.toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password changed successfully"));
    }

    // --- Password Reset Tests ---

    @Test
    void forgotPassword_ReturnsOk() throws Exception {
        ForgotPasswordRequest request = new ForgotPasswordRequest("test@example.com");
        doNothing().when(authService).forgotPassword(any(ForgotPasswordRequest.class));

        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password reset OTP sent to your email"));
    }

    @Test
    void verifyOtp_ForForgotPassword_ReturnsResetToken() throws Exception {
        VerifyOtpRequest request = new VerifyOtpRequest("test@example.com", "123456", OtpPurpose.FORGOT_PASSWORD);
        VerifyOtpResponse response = new VerifyOtpResponse("reset-token");

        when(authService.verifyOtpForPasswordReset(eq("test@example.com"), eq("123456")))
                .thenReturn(response);

        mockMvc.perform(post("/api/auth/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.resetToken").value("reset-token"));
    }

    @Test
    void resetPassword_ReturnsOk() throws Exception {
        ResetPasswordRequest request = new ResetPasswordRequest("newPass", "newPass", false);
        doNothing().when(authService).resetPassword(eq("valid-reset-token"), any(ResetPasswordRequest.class));

        mockMvc.perform(post("/api/auth/reset-password")
                        .header("Authorization", "Bearer valid-reset-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password reset successfully"));
    }
}
