package com.cigama.auth0.event.dto;


import java.io.Serializable;

/**
 * Event published to the forgot-password Redis Stream when a password reset is requested.
 * The lockKey field allows the listener to clean up the Redis cache on email delivery failure.
 */
/**
 * Event published to the forgot-password Redis Stream when a password reset is requested.
 * The lockKey field allows the listener to clean up the Redis cache on email delivery failure.
 */
public record ForgotPasswordEvent(
    String email,
    String lockKey,
    String otpCode
) implements Serializable {}
