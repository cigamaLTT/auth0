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
import tools.jackson.databind.ObjectMapper;

import java.util.List;

/**
 * Listener for Registration-related events from Redis Streams.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RegistrationStreamListener
        implements StreamListener<String, ObjectRecord<String, String>> {

    private final EmailService emailService;
    private final RedisTemplate<String, Object> streamRedisTemplate;
    private final ObjectMapper objectMapper;

    @Value("${app.registration.lock-prefix-username}")
    private String usernameLockPrefix;

    @Override
    public void onMessage(ObjectRecord<String, String> message) {
        String eventJson = message.getValue();
        log.info("Received registration event: {}", eventJson);
        
        try {
            PendingRegistrationEvent event = objectMapper.readValue(eventJson, PendingRegistrationEvent.class);
            log.info("Processing pending registration for: {}", event.getEmail());
            
            try {
                emailService.sendOtpEmail(event.getEmail(), event.getOtpCode());
            } catch (Exception e) {
                log.error("Failed to send OTP email: {}. Reverting Redis locks.", e.getMessage());

                String emailLockKey = event.getRegistrationId();
                String usernameLockKey = usernameLockPrefix + event.getUsername();
                streamRedisTemplate.delete(List.of(emailLockKey, usernameLockKey));
            }
        } catch (Exception e) {
            log.error("Invalid registration event data: {}", e.getMessage());
        }
    }
}
