package com.cigama.auth0.service;

public interface TokenBlacklistService {

    // --- Core Methods ---

    void blacklistToken(String token, long ttlMillis);

    boolean isBlacklisted(String token);
}
