package com.cigama.auth0.event.dto;


import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Event for tracking general login activity (success/failure).
 */
/**
 * Event for tracking general login activity (success/failure).
 */
public record LoginTrackerEvent(
    String email,
    boolean success,
    String ipAddress,
    String deviceId,
    LocalDateTime timestamp,
    String failureReason
) implements Serializable {}
