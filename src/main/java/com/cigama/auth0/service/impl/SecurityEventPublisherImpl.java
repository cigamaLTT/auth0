package com.cigama.auth0.service.impl;

import com.cigama.auth0.event.dto.AccountLockoutEvent;
import com.cigama.auth0.service.EventPublisherService;
import com.cigama.auth0.service.SecurityEventPublisher;
import com.cigama.auth0.util.Constants;
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
    private final EventPublisherService eventPublisherService;

    @Value("${app.security.stream-key:auth:security:stream}")
    private String securityStreamKey;

    public SecurityEventPublisherImpl(
            @Lazy @Qualifier("streamRedisTemplate") RedisTemplate<String, Object> streamRedisTemplate,
            EventPublisherService eventPublisherService) {
        this.streamRedisTemplate = streamRedisTemplate;
        this.eventPublisherService = eventPublisherService;
    }

    @Override
    public void publishAccountLockout(String email, String ipAddress, String reason) {
        AccountLockoutEvent event = new AccountLockoutEvent(email, ipAddress, Constants.UNKNOWN, LocalDateTime.now());
        eventPublisherService.publishToStream(securityStreamKey, event);
    }
}
