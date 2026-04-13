package com.cigama.auth0.dto.cache;


import java.io.Serializable;

/**
 * Transient DTO for caching a pending password reset OTP in Redis.
 * Exists only during the OTP validity window; deleted on verification or TTL expiry.
 */
/**
 * Transient DTO for caching a pending password reset OTP in Redis.
 * Exists only during the OTP validity window; deleted on verification or TTL expiry.
 */
public record PendingPasswordResetData(
    String email,
    String otpCode
) implements Serializable {}
