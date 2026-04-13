package com.cigama.auth0.service;

import com.cigama.auth0.dto.request.ClientMetadata;
import com.cigama.auth0.dto.request.ForgotPasswordRequest;
import com.cigama.auth0.dto.request.LoginRequest;
import com.cigama.auth0.dto.request.RegisterRequest;
import com.cigama.auth0.dto.request.ResetPasswordRequest;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.dto.response.VerifyOtpResponse;

public interface AuthService {

    // --- Core Methods ---

    void register(RegisterRequest request, String apiKey);

    void verifyOtp(String email, String otpCode);

    TokenResponse login(LoginRequest request, String apiKey, ClientMetadata metadata);

    TokenResponse refresh(String refreshToken, ClientMetadata metadata);

    void logout(String accessToken, String refreshToken);

    // --- Password Reset ---

    void forgotPassword(ForgotPasswordRequest request);

    VerifyOtpResponse verifyOtpForPasswordReset(String email, String otpCode);

    void resetPassword(String resetToken, ResetPasswordRequest request);
}

