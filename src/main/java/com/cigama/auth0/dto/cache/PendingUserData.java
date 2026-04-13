package com.cigama.auth0.dto.cache;


import java.io.Serializable;
import java.time.LocalDate;

/**
 * Transient DTO dedicated to storing pending registration payload in Redis.
 * Only exists briefly during the 15-minute OTP window.
 */
/**
 * Transient DTO dedicated to storing pending registration payload in Redis.
 * Only exists briefly during the 15-minute OTP window.
 */
public record PendingUserData(
    String email,
    String phoneNumber,
    String password, // pre-encoded password
    String firstName,
    String lastName,
    String username,
    LocalDate dateOfBirth,
    String otpCode,
    String clientId // Optional, to associate with a calling client after verification
) implements Serializable {}
