package com.cigama.auth0.entity;

import com.cigama.auth0.exception.CustomException;
import org.springframework.http.HttpStatus;

import java.util.Arrays;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * Enum representing supported user security settings and their corresponding
 * operations on the UserSecuritySetting entity.
 */
public enum SecuritySettingType {
    PASSWORD("REQUIRE_OTP_FOR_PASSWORD",
            UserSecuritySetting::getRequireOtpForPassword,
            UserSecuritySetting::setRequireOtpForPassword),
    EMAIL("REQUIRE_OTP_FOR_EMAIL",
            UserSecuritySetting::getRequireOtpForEmail,
            UserSecuritySetting::setRequireOtpForEmail),
    PHONE("REQUIRE_OTP_FOR_PHONE",
            UserSecuritySetting::getRequireOtpForPhone,
            UserSecuritySetting::setRequireOtpForPhone);

    private final String name;
    private final Function<UserSecuritySetting, Boolean> getter;
    private final BiConsumer<UserSecuritySetting, Boolean> setter;

    SecuritySettingType(String name,
            Function<UserSecuritySetting, Boolean> getter,
            BiConsumer<UserSecuritySetting, Boolean> setter) {
        this.name = name;
        this.getter = getter;
        this.setter = setter;
    }

    public String getName() {
        return name;
    }

    public boolean getValue(UserSecuritySetting setting) {
        return Boolean.TRUE.equals(getter.apply(setting));
    }

    public void setValue(UserSecuritySetting setting, boolean value) {
        setter.accept(setting, value);
    }

    public static SecuritySettingType fromName(String name) {
        return Arrays.stream(values())
                .filter(s -> s.name.equalsIgnoreCase(name))
                .findFirst()
                .orElseThrow(() -> new CustomException(HttpStatus.BAD_REQUEST, "Unknown security setting: " + name));
    }
}
