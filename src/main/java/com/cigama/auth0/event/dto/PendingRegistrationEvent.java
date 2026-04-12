package com.cigama.auth0.event.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * Event triggered when a user registration is pending (awaiting OTP/Verification).
 * Payload is intended to be stored in Redis Streams as JSON.
 * Note: registrationId represents the Redis key for the pending payload.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PendingRegistrationEvent implements Serializable {
    private String email;
    private String username;
    private String registrationId;
    private String otpCode;
}
