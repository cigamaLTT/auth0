package com.cigama.auth0.service;

import com.cigama.auth0.entity.SecuritySettingType;
import java.util.UUID;

/**
 * Service for managing user security settings.
 */
public interface SecuritySettingService {
    void requestSecuritySettingUpdate(UUID userId, SecuritySettingType settingType);
    void verifySecuritySettingUpdate(UUID userId, SecuritySettingType settingType, boolean targetValue, String otpCode);
    boolean isOtpRequired(UUID userId, SecuritySettingType settingType);
}
