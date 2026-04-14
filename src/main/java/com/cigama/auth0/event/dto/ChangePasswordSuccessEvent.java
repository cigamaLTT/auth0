package com.cigama.auth0.event.dto;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Event triggered when a user changes their password successfully.
 */
public record ChangePasswordSuccessEvent(
        String email,
        String ipAddress,
        LocalDateTime timestamp,
        SecurityEventType type
) implements Serializable {
    public ChangePasswordSuccessEvent(String email, String ipAddress, LocalDateTime timestamp) {
        this(email, ipAddress, timestamp, SecurityEventType.PASSWORD_CHANGE_SUCCESS);
    }
}
