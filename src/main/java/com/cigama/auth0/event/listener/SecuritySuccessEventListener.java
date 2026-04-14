package com.cigama.auth0.event.listener;

import com.cigama.auth0.event.dto.ChangePasswordSuccessEvent;
import com.cigama.auth0.event.dto.PasswordResetSuccessEvent;
import com.cigama.auth0.service.EmailService;
import com.cigama.auth0.event.dto.SecurityEventType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.stream.ObjectRecord;
import org.springframework.data.redis.stream.StreamListener;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Specialized listener for successful security-related action events.
 * Sends confirmation emails when a user successfully changes or resets their password.
 */
@Component
public class SecuritySuccessEventListener
        implements StreamListener<String, ObjectRecord<String, String>> {

    private static final Logger log = LoggerFactory.getLogger(SecuritySuccessEventListener.class);

    private final EmailService emailService;
    private final ObjectMapper objectMapper;

    public SecuritySuccessEventListener(EmailService emailService, ObjectMapper objectMapper) {
        this.emailService = emailService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void onMessage(ObjectRecord<String, String> message) {
        try {
            JsonNode node = objectMapper.readTree(message.getValue());
            if (!node.has("type")) return;

            String type = node.get("type").asText();

            if (SecurityEventType.PASSWORD_CHANGE_SUCCESS.name().equals(type)) {
                ChangePasswordSuccessEvent event = objectMapper.treeToValue(node, ChangePasswordSuccessEvent.class);
                emailService.sendPasswordChangedEmail(event.email());
            } else if (SecurityEventType.PASSWORD_RESET_SUCCESS.name().equals(type)) {
                PasswordResetSuccessEvent event = objectMapper.treeToValue(node, PasswordResetSuccessEvent.class);
                emailService.sendPasswordChangedEmail(event.email());
            }
        } catch (Exception e) {
            log.error("Failed to process security success event: {}", e.getMessage());
        }
    }
}
