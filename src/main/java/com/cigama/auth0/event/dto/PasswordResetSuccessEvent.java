package com.cigama.auth0.event.dto;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Event triggered when a user resets their password successfully.
 */
public record PasswordResetSuccessEvent(
        String email,
        String ipAddress,
        LocalDateTime timestamp,
        SecurityEventType type
) implements Serializable {
    public PasswordResetSuccessEvent(String email, String ipAddress, LocalDateTime timestamp) {
        this(email, ipAddress, timestamp, SecurityEventType.PASSWORD_RESET_SUCCESS);
    }
}
