package com.cigama.auth0.service.impl;

import com.cigama.auth0.entity.User;
import com.cigama.auth0.entity.SecuritySettingType;
import com.cigama.auth0.event.dto.SecuritySettingOtpEvent;
import org.springframework.context.annotation.Lazy;
import org.springframework.beans.factory.annotation.Qualifier;
import com.cigama.auth0.exception.CustomException;
import com.cigama.auth0.repository.UserRepository;
import com.cigama.auth0.service.SecuritySettingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.stream.RecordId;
import org.springframework.data.redis.connection.stream.StreamRecords;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class SecuritySettingServiceImpl implements SecuritySettingService {

    private static final Logger log = LoggerFactory.getLogger(SecuritySettingServiceImpl.class);

    private final UserRepository userRepository;
    private final RedisTemplate<String, Object> streamRedisTemplate;
    private final ObjectMapper objectMapper;

    @Value("${app.security.stream-key:auth:security:stream}")
    private String securityStreamKey;

    public SecuritySettingServiceImpl(UserRepository userRepository,
            @Lazy @Qualifier("streamRedisTemplate") RedisTemplate<String, Object> streamRedisTemplate,
            ObjectMapper objectMapper) {
        this.userRepository = userRepository;
        this.streamRedisTemplate = streamRedisTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public void requestSecuritySettingUpdate(UUID userId, String settingName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(HttpStatus.NOT_FOUND, "User not found"));

        String otpCode = String.format("%06d", new SecureRandom().nextInt(999999));
        String redisKey = "auth:setting_otp:" + userId + ":" + settingName;
        log.info("Requesting security setting update for user: {}, setting: {}, OTP: {}", userId, settingName, otpCode);

        streamRedisTemplate.opsForValue().set(redisKey, otpCode, Duration.ofMinutes(15));

        publishToStream(securityStreamKey,
                new SecuritySettingOtpEvent(user.getEmail(), settingName, otpCode, LocalDateTime.now()));
    }

    @Override
    @Transactional
    public void verifySecuritySettingUpdate(UUID userId, String settingName, boolean targetValue, String otpCode) {
        String redisKey = "auth:setting_otp:" + userId + ":" + settingName;
        Object cachedOtp = streamRedisTemplate.opsForValue().get(redisKey);

        if (cachedOtp == null || !cachedOtp.toString().equals(otpCode)) {
            throw new CustomException(HttpStatus.BAD_REQUEST, "Invalid or expired OTP");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(HttpStatus.NOT_FOUND, "User not found"));

        SecuritySettingType.fromName(settingName).setValue(user.getSecuritySetting(), targetValue);

        userRepository.save(user);
        streamRedisTemplate.delete(redisKey);
    }

    @Override
    public boolean isOtpRequired(UUID userId, String settingName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(HttpStatus.NOT_FOUND, "User not found"));

        return SecuritySettingType.fromName(settingName).getValue(user.getSecuritySetting());
    }

    private void publishToStream(String streamKey, Object event) {
        try {
            String eventJson = objectMapper.writeValueAsString(event);
            streamRedisTemplate.opsForStream().add(
                    StreamRecords.newRecord().in(streamKey).ofObject(eventJson).withId(RecordId.autoGenerate()));
        } catch (Exception e) {
            log.error("Failed to publish event to {}: {}", streamKey, e.getMessage());
        }
    }
}
