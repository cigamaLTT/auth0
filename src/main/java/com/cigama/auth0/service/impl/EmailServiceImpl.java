package com.cigama.auth0.service.impl;

import com.cigama.auth0.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender emailSender;

    @Override
    public void sendOtpEmail(String toEmail, String otpCode) {
        log.info("Preparing to send OTP email to {}", toEmail);
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(toEmail);
            message.setSubject("Your Auth0 Verification Code");
            message.setText("Here is your 6-digit OTP code: " + otpCode + "\n\nThis code will expire in 15 minutes.");
            
            emailSender.send(message);
            log.info("OTP Email successfully sent to {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send OTP to {}: {}", toEmail, e.getMessage());
            throw new RuntimeException("Email delivery failed", e);
        }
    }
}
