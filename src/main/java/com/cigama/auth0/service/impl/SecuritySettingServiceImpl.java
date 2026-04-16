package com.cigama.auth0.service.impl;

import com.cigama.auth0.entity.User;
import com.cigama.auth0.entity.SecuritySettingType;
import com.cigama.auth0.event.dto.SecuritySettingOtpEvent;
import org.springframework.context.annotation.Lazy;
import org.springframework.beans.factory.annotation.Qualifier;
import com.cigama.auth0.exception.CustomException;
import com.cigama.auth0.repository.UserRepository;
import com.cigama.auth0.service.EventPublisherService;
import com.cigama.auth0.service.SecuritySettingService;
import com.cigama.auth0.util.Constants;
import com.cigama.auth0.util.OtpUtils;
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
    private final EventPublisherService eventPublisherService;

    @Value("${app.security.stream-key:auth:security:stream}")
    private String securityStreamKey;

    public SecuritySettingServiceImpl(UserRepository userRepository,
            @Lazy @Qualifier("streamRedisTemplate") RedisTemplate<String, Object> streamRedisTemplate,
            EventPublisherService eventPublisherService) {
        this.userRepository = userRepository;
        this.streamRedisTemplate = streamRedisTemplate;
        this.eventPublisherService = eventPublisherService;
    }

    @Override
    public void requestSecuritySettingUpdate(UUID userId, SecuritySettingType settingType) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(HttpStatus.NOT_FOUND, "User not found"));

        String otpCode = OtpUtils.generateOtp();
        String redisKey = Constants.REDIS_AUTH_SETTING_OTP_PREFIX + userId + ":" + settingType.getName();
        log.info("Requesting security setting update for user: {}, setting: {}, OTP: {}", userId, settingType.getName(), otpCode);

        streamRedisTemplate.opsForValue().set(redisKey, otpCode, Constants.DEFAULT_SECURITY_OTP_EXPIRATION);

        eventPublisherService.publishToStream(securityStreamKey,
                new SecuritySettingOtpEvent(user.getEmail(), settingType.getName(), otpCode, LocalDateTime.now()));
    }

    @Override
    @Transactional
    public void verifySecuritySettingUpdate(UUID userId, SecuritySettingType settingType, boolean targetValue, String otpCode) {
        String redisKey = Constants.REDIS_AUTH_SETTING_OTP_PREFIX + userId + ":" + settingType.getName();
        Object cachedOtp = streamRedisTemplate.opsForValue().get(redisKey);

        if (cachedOtp == null || !cachedOtp.toString().equals(otpCode)) {
            throw new CustomException(HttpStatus.BAD_REQUEST, "Invalid or expired OTP");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(HttpStatus.NOT_FOUND, "User not found"));

        settingType.setValue(user.getSecuritySetting(), targetValue);

        userRepository.save(user);
        streamRedisTemplate.delete(redisKey);
    }

    @Override
    public boolean isOtpRequired(UUID userId, SecuritySettingType settingType) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(HttpStatus.NOT_FOUND, "User not found"));

        return settingType.getValue(user.getSecuritySetting());
    }
}
