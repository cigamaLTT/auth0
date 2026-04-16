package com.cigama.auth0.dto.request;

import com.cigama.auth0.entity.SecuritySettingType;

/**
 * Request to verify and apply a security setting update.
 */
public record VerifySecuritySettingRequest(
        SecuritySettingType settingType,
        boolean targetValue,
        String otpCode
) {}
