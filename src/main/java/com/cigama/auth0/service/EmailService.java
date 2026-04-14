package com.cigama.auth0.service;

public interface EmailService {
    void sendOtpEmail(String toEmail, String otpCode);
    void sendPasswordResetEmail(String toEmail, String otpCode);
    void sendPasswordChangedEmail(String toEmail);
    void sendAccountLockoutEmail(String toEmail, String ipAddress);
    void sendWelcomeEmail(String toEmail, String username);
}


