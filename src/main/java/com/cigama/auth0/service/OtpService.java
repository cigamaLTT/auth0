package com.cigama.auth0.service;

/**
 * Service for managing OTP lifecycle and temporary data persistence in Redis.
 */
public interface OtpService {
    String generateAndSaveRegistrationOtp(com.cigama.auth0.dto.cache.PendingUserData pendingData);
    com.cigama.auth0.dto.cache.PendingUserData verifyRegistrationOtp(String email, String otpCode);
    
    String generateAndSavePasswordResetOtp(String email);
    void verifyPasswordResetOtp(String email, String otpCode);
}
