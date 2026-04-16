package com.cigama.auth0.service;

import com.cigama.auth0.dto.cache.PendingUserData;

/**
 * Service for managing OTP lifecycle and temporary data persistence in Redis.
 */
public interface OtpService {
    String generateAndSaveRegistrationOtp(PendingUserData pendingData);
    PendingUserData verifyRegistrationOtp(String email, String otpCode);
    
    String generateAndSavePasswordResetOtp(String email);
    void verifyPasswordResetOtp(String email, String otpCode);
}
