package com.cigama.auth0.event.listener;

import com.cigama.auth0.event.dto.ForgotPasswordEvent;
import com.cigama.auth0.service.EmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.stream.ObjectRecord;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.stream.StreamListener;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Listener for forgot-password events from the Redis Stream.
 * Consumes ForgotPasswordEvent and delivers the OTP email asynchronously.
 * On delivery failure, deletes the Redis lock so the user can retry.
 */
@Component
public class ForgotPasswordStreamListener
        implements StreamListener<String, ObjectRecord<String, String>> {

    private static final Logger log = LoggerFactory.getLogger(ForgotPasswordStreamListener.class);

    // --- Variables ---

    private final EmailService emailService;
    private final RedisTemplate<String, Object> streamRedisTemplate;
    private final ObjectMapper objectMapper;

    public ForgotPasswordStreamListener(EmailService emailService,
                                        RedisTemplate<String, Object> streamRedisTemplate,
                                        ObjectMapper objectMapper) {
        this.emailService = emailService;
        this.streamRedisTemplate = streamRedisTemplate;
        this.objectMapper = objectMapper;
    }

    // --- Methods ---

    @Override
    public void onMessage(ObjectRecord<String, String> message) {
        String eventJson = message.getValue();
        log.info("Received forgot-password event: {}", eventJson);

        try {
            ForgotPasswordEvent event = objectMapper.readValue(eventJson, ForgotPasswordEvent.class);
            log.info("Processing password reset request for: {}", event.email());

            try {
                emailService.sendPasswordResetEmail(event.email(), event.otpCode());
            } catch (Exception e) {
                log.error("Failed to send password reset email to {}: {}. Reverting Redis lock.", event.email(), e.getMessage());
                streamRedisTemplate.delete(event.lockKey());
            }
        } catch (Exception e) {
            log.error("Invalid forgot-password event data: {}", e.getMessage());
        }
    }
}
