package com.cigama.auth0.event.listener;

import com.cigama.auth0.event.dto.PendingRegistrationEvent;
import com.cigama.auth0.service.EmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
@Component
public class RegistrationStreamListener
        implements StreamListener<String, ObjectRecord<String, String>> {

    private static final Logger log = LoggerFactory.getLogger(RegistrationStreamListener.class);

    // --- Variables ---

    private final EmailService emailService;
    private final RedisTemplate<String, Object> streamRedisTemplate;
    private final ObjectMapper objectMapper;

    public RegistrationStreamListener(EmailService emailService,
                                      RedisTemplate<String, Object> streamRedisTemplate,
                                      ObjectMapper objectMapper) {
        this.emailService = emailService;
        this.streamRedisTemplate = streamRedisTemplate;
        this.objectMapper = objectMapper;
    }

    @Value("${app.registration.lock-prefix-username}")
    private String usernameLockPrefix;

    // --- Methods ---

    @Override
    public void onMessage(ObjectRecord<String, String> message) {
        String eventJson = message.getValue();
        log.info("Received registration event: {}", eventJson);
        
        try {
            PendingRegistrationEvent event = objectMapper.readValue(eventJson, PendingRegistrationEvent.class);
            log.info("Processing pending registration for: {}", event.email());
            
            try {
                emailService.sendOtpEmail(event.email(), event.otpCode());
            } catch (Exception e) {
                log.error("Failed to send OTP email: {}. Reverting Redis locks.", e.getMessage());

                String emailLockKey = event.registrationId();
                String usernameLockKey = usernameLockPrefix + event.username();
                streamRedisTemplate.delete(List.of(emailLockKey, usernameLockKey));
            }
        } catch (Exception e) {
            log.error("Invalid registration event data: {}", e.getMessage());
        }
    }
}
