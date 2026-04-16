package com.cigama.auth0.util;

import java.security.SecureRandom;

public final class OtpUtils {

    private static final SecureRandom RANDOM = new SecureRandom();

    private OtpUtils() {}

    /**
     * Generates a random numeric OTP code.
     *
     * @return the generated OTP code as a string
     */
    public static String generateOtp() {
        return String.format(Constants.OTP_FORMAT, RANDOM.nextInt(Constants.OTP_MAX_RANGE));
    }
}
