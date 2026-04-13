package com.cigama.auth0.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

/**
 * Intermediate DTO to decouple Service Layer from HttpServletRequest.
 * Contains extracted metadata about the client's origin and device.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientMetadata {
    private String ipAddress;
    private String userAgent;
    private UUID deviceId;
    private String deviceName;
}
