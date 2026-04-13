package com.cigama.auth0.dto.request;


import com.cigama.auth0.validation.ConfigurableLength;
import jakarta.validation.constraints.*;

import java.util.UUID;


public class LoginRequest {

    ///  -- Credentials --

    @NotBlank(message = "Email or Username is required")
    private String emailOrUsername;

    @NotBlank(message = "Password is required")
    @ConfigurableLength(minKey = "app.policy.password-min-length")
    @Pattern(
            regexp = "^(?=.*[A-Z]).+$",
            message = "Password must contain at least 1 uppercase letter"
    )
    private String password;

    private UUID deviceId;

    private String deviceName;

    public String getEmailOrUsername() {
        return emailOrUsername;
    }

    public void setEmailOrUsername(String emailOrUsername) {
        this.emailOrUsername = emailOrUsername;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
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
