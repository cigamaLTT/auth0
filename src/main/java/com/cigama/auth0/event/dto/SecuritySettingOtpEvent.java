package com.cigama.auth0.event.dto;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Event triggered when an OTP is generated for updating a user security setting.
 */
public record SecuritySettingOtpEvent(
        String email,
        String settingName,
        String otpCode,
        LocalDateTime timestamp,
        SecurityEventType type
) implements Serializable {
    public SecuritySettingOtpEvent(String email, String settingName, String otpCode, LocalDateTime timestamp) {
        this(email, settingName, otpCode, timestamp, SecurityEventType.SETTING_UPDATE_OTP);
    }
}
