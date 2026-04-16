package com.cigama.auth0.service.impl;

import com.cigama.auth0.event.dto.AccountLockoutEvent;
import com.cigama.auth0.service.SecurityEventPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.stream.RecordId;
import org.springframework.data.redis.connection.stream.StreamRecords;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Lazy;
import org.springframework.beans.factory.annotation.Qualifier;

import java.time.LocalDateTime;

@Service
public class SecurityEventPublisherImpl implements SecurityEventPublisher {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventPublisherImpl.class);

    private final RedisTemplate<String, Object> streamRedisTemplate;
    private final ObjectMapper objectMapper;

    @Value("${app.security.stream-key:auth:security:stream}")
    private String securityStreamKey;

    public SecurityEventPublisherImpl(
            @Lazy @Qualifier("streamRedisTemplate") RedisTemplate<String, Object> streamRedisTemplate,
            ObjectMapper objectMapper) {
        this.streamRedisTemplate = streamRedisTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public void publishAccountLockout(String email, String ipAddress, String reason) {
        AccountLockoutEvent event = new AccountLockoutEvent(email, ipAddress, "unknown", LocalDateTime.now());
        publishToStream(securityStreamKey, event);
    }

    private void publishToStream(String streamKey, Object event) {
        try {
            String eventJson = objectMapper.writeValueAsString(event);
            streamRedisTemplate.opsForStream().add(
                    StreamRecords.newRecord().in(streamKey).ofObject(eventJson).withId(RecordId.autoGenerate()));
        } catch (Exception e) {
            log.error("Failed to publish security event to {}: {}", streamKey, e.getMessage());
        }
    }
}
