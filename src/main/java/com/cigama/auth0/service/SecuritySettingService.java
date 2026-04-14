package com.cigama.auth0.service;

import java.util.UUID;

/**
 * Service for managing user security settings.
 */
public interface SecuritySettingService {
    void requestSecuritySettingUpdate(UUID userId, String settingName);
    void verifySecuritySettingUpdate(UUID userId, String settingName, boolean targetValue, String otpCode);
    boolean isOtpRequired(UUID userId, String settingName);
}
