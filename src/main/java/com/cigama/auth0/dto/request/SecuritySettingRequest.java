package com.cigama.auth0.dto.request;

/**
 * Request to initiate a security setting update.
 */
public record SecuritySettingRequest(
        String settingName
) {}
