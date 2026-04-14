package com.cigama.auth0.service.impl;

import com.cigama.auth0.service.RateLimitService;
import com.cigama.auth0.util.RedisLuaScripts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Service to handle request rate limiting using Redis sliding window algorithm.
 */
@Service
public class RateLimitServiceImpl implements RateLimitService {

    // --- Fields ---

    private final RedisTemplate<String, Object> streamRedisTemplate;

    @Value("${app.rate-limit.enabled:true}")
    private boolean enabled;

    @Value("${app.rate-limit.requests-per-second:10}")
    private int requestsPerSecond;

    public RateLimitServiceImpl(RedisTemplate<String, Object> streamRedisTemplate) {
        this.streamRedisTemplate = streamRedisTemplate;
    }

    // --- Methods ---

    /**
     * Checks if a request identified by the key (e.g., IP) is allowed based on the rate limit.
     */
    @Override
    public boolean isAllowed(String key) {
        if (!enabled) {
            return true;
        }

        String redisKey = "rate_limit:ip:" + key;
        long now = System.currentTimeMillis();
        long window = 1000; // 1 second window

        Long result = streamRedisTemplate.execute(
                new DefaultRedisScript<>(RedisLuaScripts.RATE_LIMIT, Long.class),
                List.of(redisKey),
                String.valueOf(now),
                String.valueOf(window),
                String.valueOf(requestsPerSecond)
        );

        return result != null && result == 1;
    }
}
