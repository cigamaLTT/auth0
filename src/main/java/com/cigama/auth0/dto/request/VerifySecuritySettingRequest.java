package com.cigama.auth0.dto.request;

/**
 * Request to verify and apply a security setting update.
 */
public record VerifySecuritySettingRequest(
        String settingName,
        boolean targetValue,
        String otpCode
) {}
