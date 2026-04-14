package com.cigama.auth0.service;

import com.cigama.auth0.dto.request.*;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.dto.response.VerifyOtpResponse;

import java.util.UUID;

public interface AuthService {

    // --- Core Methods ---

    void register(RegisterRequest request, String apiKey);

    void verifyOtp(String email, String otpCode);

    TokenResponse login(LoginRequest request, String apiKey, ClientMetadata metadata);

    TokenResponse refresh(String refreshTokenRaw, ClientMetadata metadata);

    void logout(String accessToken);

    void changePassword(UUID userId, ChangePasswordRequest request);

    // --- Password Reset ---

    void forgotPassword(ForgotPasswordRequest request);

    VerifyOtpResponse verifyOtpForPasswordReset(String email, String otpCode);

    void resetPassword(String resetToken, ResetPasswordRequest request);
}
