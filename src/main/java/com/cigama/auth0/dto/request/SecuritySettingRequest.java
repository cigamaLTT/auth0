package com.cigama.auth0.dto.request;

import com.cigama.auth0.entity.SecuritySettingType;

/**
 * Request to initiate a security setting update.
 */
public record SecuritySettingRequest(
        SecuritySettingType settingType
) {}
