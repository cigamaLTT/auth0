package com.cigama.auth0.event.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * Event published to the forgot-password Redis Stream when a password reset is requested.
 * The lockKey field allows the listener to clean up the Redis cache on email delivery failure.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ForgotPasswordEvent implements Serializable {
    private String email;
    private String lockKey;
    private String otpCode;
}
