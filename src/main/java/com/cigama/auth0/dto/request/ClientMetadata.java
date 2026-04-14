package com.cigama.auth0.dto.request;


import java.util.UUID;

/**
 * Intermediate DTO to decouple Service Layer from HttpServletRequest.
 * Contains extracted metadata about the client's origin and device.
 */
/**
 * Intermediate DTO to decouple Service Layer from HttpServletRequest.
 * Contains extracted metadata about the client's origin and device.
 */
public class ClientMetadata {
    private String ipAddress;
    private String userAgent;
    private UUID deviceId;
    private String deviceName;

    public ClientMetadata() {}

    public ClientMetadata(String ipAddress, String userAgent) {
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
    }

    public ClientMetadata(String ipAddress, String userAgent, UUID deviceId, String deviceName) {
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.deviceId = deviceId;
        this.deviceName = deviceName;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public UUID getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(UUID deviceId) {
        this.deviceId = deviceId;
    }

    public String getDeviceName() {
        return deviceName;
    }

    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }
}
