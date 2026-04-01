package com.cigama.auth0.service;

import com.cigama.auth0.dto.request.LoginRequest;
import com.cigama.auth0.dto.request.RegisterRequest;
import com.cigama.auth0.dto.response.TokenResponse;

public interface AuthService {

    // --- Core Methods ---

    void register(RegisterRequest request, String apiKey);

    TokenResponse login(LoginRequest request, String apiKey);

    TokenResponse refresh(String refreshToken);

    void logout(String accessToken, String refreshToken);
}
