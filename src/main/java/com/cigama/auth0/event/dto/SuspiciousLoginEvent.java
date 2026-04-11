package com.cigama.auth0.event.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Event triggered when a login attempt is flagged as suspicious.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SuspiciousLoginEvent implements Serializable {
    private String email;
    private String deviceId;
    private String ipAddress;
    private String userAgent;
    private LocalDateTime timestamp;
    private String reason;
}
