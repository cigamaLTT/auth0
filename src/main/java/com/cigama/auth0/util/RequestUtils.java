package com.cigama.auth0.util;

import com.cigama.auth0.dto.request.ClientMetadata;
import com.cigama.auth0.dto.request.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;

import java.util.UUID;

/**
 * Utility for extracting metadata from HttpServletRequest.
 */
public final class RequestUtils {

    private RequestUtils() {}

    /**
     * Extracts client metadata from the request and headers.
     *
     * @param request      The servlet request.
     * @param loginRequest Optional login request containing explicit device info.
     * @return A ClientMetadata DTO.
     */
    public static ClientMetadata extractMetadata(HttpServletRequest request, LoginRequest loginRequest) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || Constants.UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }

        // Handle multiple IPs in X-Forwarded-For
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }

        UUID deviceId = null;
        String deviceName = null;

        // Priority 1: Headers (X-Device-Id)
        String headerDeviceId = request.getHeader(Constants.DEVICE_ID_HEADER);
        if (headerDeviceId != null && !headerDeviceId.isEmpty()) {
            try {
                deviceId = UUID.fromString(headerDeviceId);
            } catch (IllegalArgumentException ignored) {}
        }
        deviceName = request.getHeader(Constants.DEVICE_NAME_HEADER);

        // Priority 2: LoginRequest (if provided)
        if (loginRequest != null) {
            if (deviceId == null) deviceId = loginRequest.deviceId();
            if (deviceName == null) deviceName = loginRequest.deviceName();
        }

        // Fallback for Device ID
        if (deviceId == null) {
            deviceId = UUID.randomUUID();
        }

        return new ClientMetadata(
                ip,
                request.getHeader(Constants.USER_AGENT_HEADER),
                deviceId,
                deviceName
        );
    }
}
