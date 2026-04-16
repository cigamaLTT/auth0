package com.cigama.auth0.util;

import java.time.Duration;

public final class Constants {

    private Constants() {}

    // Authentication & Security
    public static final String UNKNOWN = "unknown";
    public static final String LOCKED = "LOCKED";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String API_KEY_HEADER = "X-Api-Key";
    public static final String DEVICE_ID_HEADER = "X-Device-Id";
    public static final String DEVICE_NAME_HEADER = "X-Device-Name";
    public static final String USER_AGENT_HEADER = "User-Agent";
    public static final String PASSWORD_RESET_PURPOSE = "PASSWORD_RESET";
    public static final String OTP_FORMAT = "%06d";
    public static final int OTP_MAX_RANGE = 999999;

    // JWT Claims
    public static final String CLAIM_USER_ID = "userId";
    public static final String CLAIM_DEVICE_ID = "deviceId";
    public static final String CLAIM_PURPOSE = "purpose";

    // Redis Key Prefixes
    public static final String REDIS_AUTH_LOCKOUT_PREFIX = "auth:lockout:";
    public static final String REDIS_AUTH_FAILED_ATTEMPTS_PREFIX = "auth:failed_attempts:";
    public static final String REDIS_AUTH_LOCK_EMAIL_PREFIX = "auth:lock:email:";
    public static final String REDIS_AUTH_LOCK_RESET_PREFIX = "auth:lock:reset:";
    public static final String REDIS_AUTH_SETTING_OTP_PREFIX = "auth:setting_otp:";

    // Default Configuration
    public static final Duration DEFAULT_SECURITY_OTP_EXPIRATION = Duration.ofMinutes(15);
}
