package com.cigama.auth0.dto.cache;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDate;

/**
 * Transient DTO dedicated to storing pending registration payload in Redis.
 * Only exists briefly during the 15-minute OTP window.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PendingUserData implements Serializable {
    private String email;
    private String phoneNumber;
    private String password; // pre-encoded password
    private String firstName;
    private String lastName;
    private String username;
    private LocalDate dateOfBirth;
    private String otpCode;
    private String clientId; // Optional, to associate with a calling client after verification
}
