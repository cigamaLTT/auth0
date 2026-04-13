package com.cigama.auth0.event.listener;

import com.cigama.auth0.event.dto.ForgotPasswordEvent;
import com.cigama.auth0.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
@Component
@RequiredArgsConstructor
public class ForgotPasswordStreamListener
        implements StreamListener<String, ObjectRecord<String, String>> {

    private final EmailService emailService;
    private final RedisTemplate<String, Object> streamRedisTemplate;
    private final ObjectMapper objectMapper;

    @Override
    public void onMessage(ObjectRecord<String, String> message) {
        String eventJson = message.getValue();
        log.info("Received forgot-password event: {}", eventJson);

        try {
            ForgotPasswordEvent event = objectMapper.readValue(eventJson, ForgotPasswordEvent.class);
            log.info("Processing password reset request for: {}", event.getEmail());

            try {
                emailService.sendPasswordResetEmail(event.getEmail(), event.getOtpCode());
            } catch (Exception e) {
                log.error("Failed to send password reset email to {}: {}. Reverting Redis lock.", event.getEmail(), e.getMessage());
                streamRedisTemplate.delete(event.getLockKey());
            }
        } catch (Exception e) {
            log.error("Invalid forgot-password event data: {}", e.getMessage());
        }
    }
}
