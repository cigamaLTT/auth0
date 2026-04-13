package com.cigama.auth0.event.dto;


import java.io.Serializable;

/**
 * Event triggered when a user registration is pending (awaiting OTP/Verification).
 * Payload is intended to be stored in Redis Streams as JSON.
 * Note: registrationId represents the Redis key for the pending payload.
 */
/**
 * Event triggered when a user registration is pending (awaiting OTP/Verification).
 * Payload is intended to be stored in Redis Streams as JSON.
 * Note: registrationId represents the Redis key for the pending payload.
 */
public record PendingRegistrationEvent(
    String email,
    String username,
    String registrationId,
    String otpCode
) implements Serializable {}
