package com.cigama.auth0.event.listener;

import com.cigama.auth0.event.dto.AccountLockoutEvent;
import com.cigama.auth0.event.dto.LoginTrackerEvent;
import com.cigama.auth0.service.SecurityEventPublisher;
import com.cigama.auth0.util.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.stream.ObjectRecord;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.stream.StreamListener;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Lazy;
import org.springframework.beans.factory.annotation.Qualifier;

import java.time.Duration;

/**
 * Handles login tracking events and implements account lockout logic.
 * Counts failed attempts in Redis and triggers lockout events.
 */
@Component
public class LoginTrackerStreamListener
        implements StreamListener<String, ObjectRecord<String, String>> {

    private static final Logger log = LoggerFactory.getLogger(LoginTrackerStreamListener.class);

    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityEventPublisher securityEventPublisher;
    private final ObjectMapper objectMapper;

    @Value("${app.login.max-failed-attempts:30}")
    private int maxFailedAttempts;

    @Value("${app.login.lockout-duration-minutes:60}")
    private int lockoutDurationMinutes;

    public LoginTrackerStreamListener(
            @Lazy @Qualifier("streamRedisTemplate") RedisTemplate<String, Object> redisTemplate,
            SecurityEventPublisher securityEventPublisher,
            ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.securityEventPublisher = securityEventPublisher;
        this.objectMapper = objectMapper;
    }

    @Override
    public void onMessage(ObjectRecord<String, String> message) {
        try {
            LoginTrackerEvent event = objectMapper.readValue(message.getValue(), LoginTrackerEvent.class);
            log.debug("Processing login tracker event for: {}", event.email());

            if (event.success()) {
                clearFailedAttempts(event.email());
            } else {
                handleFailedAttempt(event);
            }
        } catch (Exception e) {
            log.error("Failed to process login tracker event: {}", e.getMessage());
        }
    }

    private void handleFailedAttempt(LoginTrackerEvent event) {
        String key = Constants.REDIS_AUTH_FAILED_ATTEMPTS_PREFIX + event.email();
        Long attempts = redisTemplate.opsForValue().increment(key);

        if (attempts != null && attempts == 1) {
            redisTemplate.expire(key, Duration.ofMinutes(lockoutDurationMinutes));
        }

        log.warn("Failed login attempt #{} for user: {}", attempts, event.email());

        if (attempts != null && attempts >= maxFailedAttempts) {
            log.error("Locking account for user: {} due to {} failed attempts", event.email(), attempts);
            String lockoutKey = Constants.REDIS_AUTH_LOCKOUT_PREFIX + event.email();
            redisTemplate.opsForValue().set(lockoutKey, Constants.LOCKED, Duration.ofMinutes(lockoutDurationMinutes));
            securityEventPublisher.publishAccountLockout(event.email(), event.ipAddress(), "max_attempts_reached");
        }
    }

    private void clearFailedAttempts(String email) {
        redisTemplate.delete(Constants.REDIS_AUTH_FAILED_ATTEMPTS_PREFIX + email);
    }
}
