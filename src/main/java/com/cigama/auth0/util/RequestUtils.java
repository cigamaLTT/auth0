package com.cigama.auth0.util;

import com.cigama.auth0.dto.request.ClientMetadata;
import com.cigama.auth0.dto.request.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.experimental.UtilityClass;

import java.util.UUID;

/**
 * Utility for extracting metadata from HttpServletRequest.
 */
@UtilityClass
public class RequestUtils {

    /**
     * Extracts client metadata from the request and headers.
     *
     * @param request      The servlet request.
     * @param loginRequest Optional login request containing explicit device info.
     * @return A ClientMetadata DTO.
     */
    public static ClientMetadata extractMetadata(HttpServletRequest request, LoginRequest loginRequest) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }

        // Handle multiple IPs in X-Forwarded-For
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }

        UUID deviceId = null;
        String deviceName = null;

        // Priority 1: Headers (X-Device-Id)
        String headerDeviceId = request.getHeader("X-Device-Id");
        if (headerDeviceId != null && !headerDeviceId.isEmpty()) {
            try {
                deviceId = UUID.fromString(headerDeviceId);
            } catch (IllegalArgumentException ignored) {}
        }
        deviceName = request.getHeader("X-Device-Name");

        // Priority 2: LoginRequest (if provided)
        if (loginRequest != null) {
            if (deviceId == null) deviceId = loginRequest.getDeviceId();
            if (deviceName == null) deviceName = loginRequest.getDeviceName();
        }

        // Fallback for Device ID
        if (deviceId == null) {
            deviceId = UUID.randomUUID();
        }

        return ClientMetadata.builder()
                .ipAddress(ip)
                .userAgent(request.getHeader("User-Agent"))
                .deviceId(deviceId)
                .deviceName(deviceName)
                .build();
    }
}
