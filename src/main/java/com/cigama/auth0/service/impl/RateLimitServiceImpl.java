package com.cigama.auth0.service.impl;

import com.cigama.auth0.service.RateLimitService;
import org.springframework.stereotype.Service;

/**
 * Placeholder implementation of RateLimitService.
 */
@Service
public class RateLimitServiceImpl implements RateLimitService {

    @Override
    public boolean isAllowed(String key) {
        // Base version: return true to avoid blocking anything during initialization
        return true;
    }
}
