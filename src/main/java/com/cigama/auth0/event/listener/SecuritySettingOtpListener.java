package com.cigama.auth0.event.listener;

import com.cigama.auth0.event.dto.SecuritySettingOtpEvent;
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
 * Specialized listener for security setting update OTP events.
 * Sends an OTP email when a user requests a change to their security settings.
 */
@Component
public class SecuritySettingOtpListener
        implements StreamListener<String, ObjectRecord<String, String>> {

    private static final Logger log = LoggerFactory.getLogger(SecuritySettingOtpListener.class);

    private final EmailService emailService;
    private final ObjectMapper objectMapper;

    public SecuritySettingOtpListener(EmailService emailService, ObjectMapper objectMapper) {
        this.emailService = emailService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void onMessage(ObjectRecord<String, String> message) {
        try {
            JsonNode node = objectMapper.readTree(message.getValue());
            if (node.has("type") && SecurityEventType.SETTING_UPDATE_OTP.name().equals(node.get("type").asText())) {
                SecuritySettingOtpEvent event = objectMapper.treeToValue(node, SecuritySettingOtpEvent.class);
                log.info("Sending Setting Update OTP: User={}, Setting={}", event.email(), event.settingName());
                emailService.sendOtpEmail(event.email(), event.otpCode());
            }
        } catch (Exception e) {
            log.error("Failed to process security setting OTP event: {}", e.getMessage());
        }
    }
}
