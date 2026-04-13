package com.cigama.auth0.dto.response;


import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Data reflecting an active session (Refresh Token) with device and origin information.
 */
/**
 * Data reflecting an active session (Refresh Token) with device and origin information.
 */
public record SessionResponse(
    UUID deviceId,
    String deviceName,
    String ipAddress,
    String userAgent,
    LocalDateTime createdAt,
    LocalDateTime lastUsedAt,
    boolean isCurrent
) {}
