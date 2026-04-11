package com.cigama.auth0.service;

/**
 * Interface for Rate Limiting logic.
 * Default implementations should return true (not blocked) during initialization.
 */
public interface RateLimitService {
    
    /**
     * Checks if a request should be allowed based on rate limits.
     * @param key Identifer for the rate limit (e.g., IP or Email)
     * @return true if allowed, false if blocked
     */
    boolean isAllowed(String key);
}
