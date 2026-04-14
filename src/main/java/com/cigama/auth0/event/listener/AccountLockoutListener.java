package com.cigama.auth0.event.listener;

import com.cigama.auth0.event.dto.AccountLockoutEvent;
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
 * Specialized listener for account lockout events.
 * Sends an email notification to the user when their account is locked.
 */
@Component
public class AccountLockoutListener
        implements StreamListener<String, ObjectRecord<String, String>> {

    private static final Logger log = LoggerFactory.getLogger(AccountLockoutListener.class);

    private final EmailService emailService;
    private final ObjectMapper objectMapper;

    public AccountLockoutListener(EmailService emailService, ObjectMapper objectMapper) {
        this.emailService = emailService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void onMessage(ObjectRecord<String, String> message) {
        try {
            JsonNode node = objectMapper.readTree(message.getValue());
            if (node.has("type") && SecurityEventType.ACCOUNT_LOCKOUT.name().equals(node.get("type").asText())) {
                AccountLockoutEvent event = objectMapper.treeToValue(node, AccountLockoutEvent.class);
                log.error("ACCOUNT LOCKED: User={}, IP={}", event.email(), event.ipAddress());
                emailService.sendAccountLockoutEmail(event.email(), event.ipAddress());
            }
        } catch (Exception e) {
            log.error("Failed to process account lockout event: {}", e.getMessage());
        }
    }
}
