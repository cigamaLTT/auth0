package com.cigama.auth0.event.listener;

import com.cigama.auth0.event.dto.PendingRegistrationEvent;
import com.cigama.auth0.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.stream.ObjectRecord;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.stream.StreamListener;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Listener for Registration-related events from Redis Streams.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RegistrationStreamListener
        implements StreamListener<String, ObjectRecord<String, PendingRegistrationEvent>> {

    private final EmailService emailService;
    private final RedisTemplate<String, Object> streamRedisTemplate;

    @Value("${app.registration.lock-prefix-username}")
    private String usernameLockPrefix;

    @Override
    public void onMessage(ObjectRecord<String, PendingRegistrationEvent> message) {
        PendingRegistrationEvent event = message.getValue();
        log.info("Processing pending registration for: {}", event.getEmail());
        try {
            emailService.sendOtpEmail(event.getEmail(), event.getOtpCode());
        } catch (Exception e) {
            log.error("Failed to process registration event: {}. Initiating Revert Lock mechanisms.", e.getMessage());

            // Trigger Revert: Cleanup Redis registration cache so user can retry
            // immediately without waiting 15 mins
            String emailLockKey = event.getRegistrationId();
            String usernameLockKey = usernameLockPrefix + event.getUsername();

            streamRedisTemplate.delete(List.of(emailLockKey, usernameLockKey));
            log.info("Reverted Redis cache locks for email: {}", event.getEmail());
        }
    }
}
