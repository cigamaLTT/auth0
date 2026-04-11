package com.cigama.auth0.event.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Event for tracking general login activity (success/failure).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginTrackerEvent implements Serializable {
    private String email;
    private boolean success;
    private String ipAddress;
    private String deviceId;
    private LocalDateTime timestamp;
    private String failureReason;
}
