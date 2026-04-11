package com.cigama.auth0.event.listener;

import com.cigama.auth0.event.dto.PendingRegistrationEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Listener for Registration-related events from Redis Streams.
 */
@Slf4j
@Component
public class RegistrationStreamListener {

    /**
     * Handles pending registration: Sends OTP via email.
     * Implements basic retry/revert logic.
     */
    public void onPendingRegistration(PendingRegistrationEvent event) {
        log.info("Processing pending registration for: {}", event.getEmail());
        try {
            // Logic to send email would go here (via EmailService)
            // If hard fail occurs, trigger compensating transaction (revert)
        } catch (Exception e) {
            log.error("Failed to process registration event: {}", e.getMessage());
            // Trigger Revert: Cleanup Redis registration cache
        }
    }
}
