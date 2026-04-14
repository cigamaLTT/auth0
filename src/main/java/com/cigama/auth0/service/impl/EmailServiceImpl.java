package com.cigama.auth0.service.impl;

import com.cigama.auth0.service.EmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import jakarta.mail.internet.MimeMessage;

@Service
public class EmailServiceImpl implements EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailServiceImpl.class);

    private final JavaMailSender emailSender;
    private final TemplateEngine templateEngine;

    public EmailServiceImpl(JavaMailSender emailSender, TemplateEngine templateEngine) {
        this.emailSender = emailSender;
        this.templateEngine = templateEngine;
    }

    // --- Public Methods ---

    @Override
    public void sendOtpEmail(String toEmail, String otpCode) {
        log.info("Preparing to send HTML OTP email to {}", toEmail);
        try {
            MimeMessage mimeMessage = emailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "UTF-8");

            Context context = new Context();
            context.setVariable("otpCode", otpCode);
            String htmlContent = templateEngine.process("otp-email", context);

            helper.setTo(toEmail);
            helper.setSubject("Your Auth0 Verification Code");
            helper.setText(htmlContent, true);

            emailSender.send(mimeMessage);
            log.info("HTML OTP Email successfully sent to {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send HTML OTP to {}: {}", toEmail, e.getMessage());
            throw new RuntimeException("Email delivery failed", e);
        }
    }

    @Override
    public void sendPasswordResetEmail(String toEmail, String otpCode) {
        log.info("Preparing to send HTML password reset email to {}", toEmail);
        try {
            MimeMessage mimeMessage = emailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "UTF-8");

            Context context = new Context();
            context.setVariable("otpCode", otpCode);
            String htmlContent = templateEngine.process("otp-email", context); // We can reuse or specialize templates

            helper.setTo(toEmail);
            helper.setSubject("Reset Your Auth0 Password");
            helper.setText(htmlContent, true);

            emailSender.send(mimeMessage);
            log.info("HTML password reset email successfully sent to {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send HTML password reset email to {}: {}", toEmail, e.getMessage());
            throw new RuntimeException("Email delivery failed", e);
        }
    }

    @Override
    public void sendPasswordChangedEmail(String toEmail) {
        log.info("Preparing to send HTML password changed notification to {}", toEmail);
        try {
            MimeMessage mimeMessage = emailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "UTF-8");

            Context context = new Context();
            String htmlContent = templateEngine.process("password-changed", context);

            helper.setTo(toEmail);
            helper.setSubject("Security Alert: Your password has been changed");
            helper.setText(htmlContent, true);

            emailSender.send(mimeMessage);
            log.info("HTML password changed notification successfully sent to {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send HTML password changed notification to {}: {}", toEmail, e.getMessage());
            throw new RuntimeException("Email delivery failed", e);
        }
    }

    @Override
    public void sendAccountLockoutEmail(String toEmail, String ipAddress) {
        log.info("Sending account lockout alert to {}", toEmail);
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject("Security Alert: Your account is locked");
        message.setText("Multiple failed login attempts were detected from IP: " + ipAddress +
                       ". Your account has been temporarily locked for security reasons.");
        emailSender.send(message);
    }

    @Override
    public void sendWelcomeEmail(String toEmail, String username) {
        log.info("Sending welcome email to {}", toEmail);
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject("Welcome to Auth0!");
        message.setText("Hi " + username + ", Your account has been verified. Welcome aboard!");
        emailSender.send(message);
    }
}

