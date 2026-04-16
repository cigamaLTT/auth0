package com.cigama.auth0.util;

import com.cigama.auth0.dto.userdetails.CustomUserDetails;

import java.util.UUID;

public final class SecurityUtils {

    private SecurityUtils() {}

    /**
     * Extracts the user ID from CustomUserDetails and converts it to UUID.
     *
     * @param userDetails the user details
     * @return the user ID as UUID
     */
    public static UUID getUserIdAsUuid(CustomUserDetails userDetails) {
        return UUID.fromString(userDetails.getUserId());
    }

    /**
     * Extracts the bearer token from the Authorization header.
     *
     * @param authorizationHeader the Authorization header value
     * @return the extracted token, or null if not a bearer token
     */
    public static String extractToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith(Constants.BEARER_PREFIX)) {
            return authorizationHeader.substring(Constants.BEARER_PREFIX.length());
        }
        return null;
    }
}
