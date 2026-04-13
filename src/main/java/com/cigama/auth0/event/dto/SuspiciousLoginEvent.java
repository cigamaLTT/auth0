package com.cigama.auth0.event.dto;


import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Event triggered when a login attempt is flagged as suspicious.
 */
/**
 * Event triggered when a login attempt is flagged as suspicious.
 */
public record SuspiciousLoginEvent(
    String email,
    String deviceId,
    String ipAddress,
    String userAgent,
    LocalDateTime timestamp,
    String reason
) implements Serializable {}
