package com.cigama.auth0.service.impl;

import com.cigama.auth0.service.TokenBlacklistService;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class TokenBlacklistServiceImpl implements TokenBlacklistService {

    // --- Variables ---

    private final RedisTemplate<String, String> redisTemplate;
    private static final String BLACKLIST_PREFIX = "blacklist:";

    public TokenBlacklistServiceImpl(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // --- Core Methods ---

    @Override
    public void blacklistToken(String token, long ttlMillis) {
        if (ttlMillis > 0) {
            redisTemplate.opsForValue().set(BLACKLIST_PREFIX + token, "true", ttlMillis, TimeUnit.MILLISECONDS);
        }
    }

    @Override
    public boolean isBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX + token));
    }
}
