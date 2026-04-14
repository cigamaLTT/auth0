package com.cigama.auth0.service;

import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.entity.ClientApp;
import com.cigama.auth0.entity.User;
import com.cigama.auth0.dto.request.ClientMetadata;

import java.util.UUID;

/**
 * Service for managing token lifecycle, including generation, hashing, and persistence.
 */
public interface TokenService {
    TokenResponse generateTokenResponse(User user, ClientApp clientApp, ClientMetadata metadata);
    void revokeTokens(UUID userId, UUID deviceId);
    void revokeAllTokens(UUID userId);
}
