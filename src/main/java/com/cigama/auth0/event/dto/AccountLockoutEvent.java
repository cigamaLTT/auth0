package com.cigama.auth0.event.dto;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Event triggered when an account is locked due to too many failed login attempts.
 */
public record AccountLockoutEvent(
        String email,
        String ipAddress,
        String deviceId,
        LocalDateTime timestamp,
        SecurityEventType type
) implements Serializable {
    public AccountLockoutEvent(String email, String ipAddress, String deviceId, LocalDateTime timestamp) {
        this(email, ipAddress, deviceId, timestamp, SecurityEventType.ACCOUNT_LOCKOUT);
    }
}
