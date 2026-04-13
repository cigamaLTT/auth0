package com.cigama.auth0.dto.cache;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * Transient DTO for caching a pending password reset OTP in Redis.
 * Exists only during the OTP validity window; deleted on verification or TTL expiry.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PendingPasswordResetData implements Serializable {
    private String email;
    private String otpCode;
}
