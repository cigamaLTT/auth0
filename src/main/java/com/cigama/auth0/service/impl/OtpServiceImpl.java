package com.cigama.auth0.service.impl;

import com.cigama.auth0.dto.cache.PendingPasswordResetData;
import com.cigama.auth0.dto.cache.PendingUserData;
import com.cigama.auth0.exception.CustomException;
import com.cigama.auth0.service.OtpService;
import com.cigama.auth0.util.OtpUtils;
import com.cigama.auth0.util.RedisLuaScripts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.security.SecureRandom;
import java.util.List;

@Service
public class OtpServiceImpl implements OtpService {

    private final RedisTemplate<String, Object> streamRedisTemplate;
    private final ObjectMapper objectMapper;

    @Value("${app.registration.otp-expiration}")
    private int registrationOtpExpiration;

    @Value("${app.registration.lock-prefix-email}")
    private String registrationEmailLockPrefix;

    @Value("${app.registration.lock-prefix-username}")
    private String registrationUsernameLockPrefix;

    @Value("${app.password-reset.otp-expiration}")
    private int passwordResetOtpExpiration;

    @Value("${app.password-reset.lock-prefix-email}")
    private String passwordResetEmailLockPrefix;

    public OtpServiceImpl(RedisTemplate<String, Object> streamRedisTemplate, ObjectMapper objectMapper) {
        this.streamRedisTemplate = streamRedisTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public String generateAndSaveRegistrationOtp(PendingUserData pendingData) {
        String payloadJson;
        try {
            payloadJson = objectMapper.writeValueAsString(pendingData);
        } catch (Exception e) {
            throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to serialize pending user data");
        }

        String emailLockKey = registrationEmailLockPrefix + pendingData.email();
        String usernameLockKey = registrationUsernameLockPrefix + pendingData.username();

        Long result = streamRedisTemplate.execute(
                new DefaultRedisScript<>(RedisLuaScripts.SET_PENDING_USER, Long.class),
                List.of(emailLockKey, usernameLockKey),
                payloadJson,
                String.valueOf(registrationOtpExpiration)
        );

        if (result == null || result == 0) {
            throw new CustomException(HttpStatus.CONFLICT, "Email or Username is already taken.");
        }

        return pendingData.otpCode();
    }

    @Override
    public PendingUserData verifyRegistrationOtp(String email, String otpCode) {
        String emailLockKey = registrationEmailLockPrefix + email;
        Object payloadObj = streamRedisTemplate.opsForValue().get(emailLockKey);

        if (payloadObj == null) {
            throw new CustomException(HttpStatus.BAD_REQUEST, "OTP expired or invalid.");
        }

        PendingUserData pendingData;
        try {
            pendingData = objectMapper.readValue(payloadObj.toString(), PendingUserData.class);
        } catch (Exception e) {
            throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to parse cached user data");
        }

        if (!pendingData.otpCode().equals(otpCode)) {
            throw new CustomException(HttpStatus.BAD_REQUEST, "Invalid OTP code.");
        }

        streamRedisTemplate.delete(List.of(emailLockKey, registrationUsernameLockPrefix + pendingData.username()));
        return pendingData;
    }

    @Override
    public String generateAndSavePasswordResetOtp(String email) {
        String otp = OtpUtils.generateOtp();
        String lockKey = passwordResetEmailLockPrefix + email;
        PendingPasswordResetData pendingData = new PendingPasswordResetData(email, otp);

        try {
            String payloadJson = objectMapper.writeValueAsString(pendingData);
            streamRedisTemplate.execute(
                    new DefaultRedisScript<>(RedisLuaScripts.SET_PENDING_RESET_OTP, Long.class),
                    List.of(lockKey), payloadJson, String.valueOf(passwordResetOtpExpiration)
            );
        } catch (Exception e) {
            throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to start password reset");
        }

        return otp;
    }

    @Override
    public void verifyPasswordResetOtp(String email, String otpCode) {
        String lockKey = passwordResetEmailLockPrefix + email;
        Object payloadObj = streamRedisTemplate.opsForValue().get(lockKey);

        if (payloadObj == null) throw new CustomException(HttpStatus.BAD_REQUEST, "OTP expired or not found");

        PendingPasswordResetData pendingData;
        try {
            pendingData = objectMapper.readValue(payloadObj.toString(), PendingPasswordResetData.class);
        } catch (Exception e) {
            throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to parse reset data");
        }

        if (!pendingData.otpCode().equals(otpCode)) throw new CustomException(HttpStatus.BAD_REQUEST, "Invalid OTP code");

        streamRedisTemplate.delete(lockKey);
    }
}
