package com.cigama.auth0.service.impl;

import com.cigama.auth0.dto.JwtPayload;
import com.cigama.auth0.dto.cache.PendingPasswordResetData;
import com.cigama.auth0.dto.cache.PendingUserData;
import com.cigama.auth0.dto.request.*;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.dto.response.VerifyOtpResponse;
import com.cigama.auth0.entity.ClientApp;
import com.cigama.auth0.entity.RefreshToken;
import com.cigama.auth0.entity.Role;
import com.cigama.auth0.entity.User;
import com.cigama.auth0.event.dto.ForgotPasswordEvent;
import com.cigama.auth0.event.dto.PendingRegistrationEvent;
import com.cigama.auth0.exception.CustomException;
import com.cigama.auth0.mapper.PasswordResetMapper;
import com.cigama.auth0.mapper.UserMapper;
import com.cigama.auth0.mapper.RegistrationMapper;
import com.cigama.auth0.repository.RefreshTokenRepository;
import com.cigama.auth0.repository.UserRepository;
import com.cigama.auth0.repository.ClientAppRepository;
import com.cigama.auth0.security.JwtTokenProvider;
import com.cigama.auth0.service.AuthService;
import com.cigama.auth0.service.TokenBlacklistService;
import com.cigama.auth0.service.ValidationService;
import com.cigama.auth0.util.RedisLuaScripts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.stream.RecordId;
import org.springframework.data.redis.connection.stream.StreamRecords;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    // --- Variables ---

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ValidationService validationService;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserMapper userMapper;
    private final RegistrationMapper registrationMapper;
    private final PasswordResetMapper passwordResetMapper;
    private final ClientAppRepository clientAppRepository;
    private final TokenBlacklistService tokenBlacklistService;
    private final RedisTemplate<String, Object> streamRedisTemplate;
    private final ObjectMapper objectMapper;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    @Value("${app.registration.otp-expiration}")
    private int otpExpiration;

    @Value("${app.registration.stream-key}")
    private String registrationStreamKey;

    @Value("${app.registration.lock-prefix-email}")
    private String emailLockPrefix;

    @Value("${app.registration.lock-prefix-username}")
    private String usernameLockPrefix;

    @Value("${app.password-reset.otp-expiration}")
    private int passwordResetOtpExpiration;

    @Value("${app.password-reset.stream-key}")
    private String passwordResetStreamKey;

    @Value("${app.password-reset.lock-prefix-email}")
    private String passwordResetEmailLockPrefix;

    // --- Public Methods ---

    /**
     * Validates unique constraints and API key, then caches the registration payload
     * in Redis and pushes an event to a Redis Stream for async email processing.
     */
    @Override
    public void register(RegisterRequest request, String apiKey) {
        ClientApp clientApp = validationService.validateRegistration(request, apiKey);
        
        String generatedOtp = String.format("%06d", new SecureRandom().nextInt(999999));
        String encodedPassword = passwordEncoder.encode(request.getPassword());
        String clientIdStr = clientApp != null ? clientApp.getClientId().toString() : null;
        
        PendingUserData pendingData = registrationMapper.toPendingUserData(request, encodedPassword, generatedOtp, clientIdStr);
        
        String payloadJson;
        try {
            payloadJson = objectMapper.writeValueAsString(pendingData);
        } catch (Exception e) {
            throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to serialize pending user data");
        }
        
        String emailLockKey = emailLockPrefix + request.getEmail();
        String usernameLockKey = usernameLockPrefix + request.getUsername();
        
        Long result = streamRedisTemplate.execute(
                new DefaultRedisScript<>(RedisLuaScripts.SET_PENDING_USER, Long.class),
                List.of(emailLockKey, usernameLockKey),
                payloadJson,
                String.valueOf(otpExpiration)
        );
        // Return 0 if the keys are already taken
        if (result == null || result == 0) {
            throw new CustomException(HttpStatus.CONFLICT, "Email or Username is already taken.");
        }
        PendingRegistrationEvent event = registrationMapper.toRegistrationEvent(request, emailLockKey, generatedOtp);
        
        try {
            String eventJson = objectMapper.writeValueAsString(event);
            streamRedisTemplate.opsForStream().add(
                    StreamRecords.newRecord()
                            .in(registrationStreamKey)
                            .ofObject(eventJson)
                            .withId(RecordId.autoGenerate())
            );
        } catch (Exception e) {
            throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to serialize registration event");
        }
    }

    /**
     * Verifies the provided OTP code against the cached payload in Redis.
     * If valid, saves the User to the database and clears the cache locks.
     */
    @Override
    @Transactional
    public void verifyOtp(String email, String otpCode) {
        String emailLockKey = emailLockPrefix + email;
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
        
        if (!pendingData.getOtpCode().equals(otpCode)) {
            throw new CustomException(HttpStatus.BAD_REQUEST, "Invalid OTP code.");
        }
        
        User user = registrationMapper.pendingToUser(pendingData);
        user.setRole(Role.UNAUTHORIZED_USER);
        user.setIsAuthorized(true);
        
        if (pendingData.getClientId() != null) {
            ClientApp clientApp = clientAppRepository.findById(UUID.fromString(pendingData.getClientId())).orElse(null);
            if (clientApp != null) {
                if (user.getClientApps() == null) {
                    user.setClientApps(new HashSet<>());
                }
                user.getClientApps().add(clientApp);
            }
        }
        
        userRepository.save(user);

        streamRedisTemplate.delete(List.of(emailLockKey, usernameLockPrefix + pendingData.getUsername()));
    }

    /**
     * Verifies credentials and client association, then issues a token pair.
     */
    @Override
    @Transactional
    public TokenResponse login(LoginRequest request, String apiKey, ClientMetadata metadata) {
        ClientApp clientApp = null;
        if (apiKey != null) {
            clientApp = validationService.validateApiKey(apiKey);
        }

        User user = validationService.validateLogin(request);
        
        if (clientApp != null) {
            if (user.getClientApps() == null) {
                user.setClientApps(new HashSet<>());
            }
            if (user.getClientApps().add(clientApp)) {
                userRepository.save(user);
            }
        }

        return generateTokenResponse(user, clientApp, metadata);
    }

    /**
     * Validates the raw refresh token, marks it as revoked, and issues a new token pair.
     */
    @Override
    @Transactional
    public TokenResponse refresh(String refreshTokenRaw, ClientMetadata metadata) {
        RefreshToken oldToken = validationService.validateRefreshToken(refreshTokenRaw);

        User user = userRepository.findById(oldToken.getUserId())
                .orElseThrow(() -> new CustomException(HttpStatus.NOT_FOUND, "User not found from valid refresh token"));

        if (!oldToken.getIsRevoked()) {
            oldToken.setIsRevoked(true);
            refreshTokenRepository.save(oldToken);
        }

        ClientApp clientApp = null;
        if (oldToken.getClientId() != null) {
            clientApp = clientAppRepository.findById(oldToken.getClientId()).orElse(null);
        }

        // Reuse device info from old token if not provided in metadata
        if (metadata != null) {
            if (metadata.getDeviceId() == null) metadata.setDeviceId(oldToken.getDeviceId());
            if (metadata.getDeviceName() == null) metadata.setDeviceName(oldToken.getDeviceName());
        }

        return generateTokenResponse(user, clientApp, metadata);
    }

    @Override
    @Transactional
    public void logout(String accessToken, String refreshTokenRaw) {
        RefreshToken refreshToken = validationService.validateRefreshToken(refreshTokenRaw);
        refreshToken.setIsRevoked(true);
        refreshTokenRepository.save(refreshToken);

        try {
            long expirationTime = jwtTokenProvider.extractAllClaims(accessToken).getExpiration().getTime();
            long remainingTtl = expirationTime - System.currentTimeMillis();

            if (remainingTtl > 0) {
                tokenBlacklistService.blacklistToken(accessToken, remainingTtl);
            }
        } catch (Exception e) {
            // Token expired or invalid, no need to blacklist
        }
    }

    // --- Password Reset ---

    /**
     * Initiates a password reset by generating an OTP, caching it in Redis, and publishing
     * a ForgotPasswordEvent to the stream for async email delivery.
     * Always returns successfully regardless of whether the email exists.
     */
    @Override
    public void forgotPassword(ForgotPasswordRequest request) {
        if (validationService.validateUserExistsByEmail(request.getEmail()).isEmpty()) {
            return;
        }

        String otp = String.format("%06d", new SecureRandom().nextInt(999999));
        String lockKey = passwordResetEmailLockPrefix + request.getEmail();

        PendingPasswordResetData pendingData = PendingPasswordResetData.builder()
                .email(request.getEmail())
                .otpCode(otp)
                .build();

        String payloadJson;
        try {
            payloadJson = objectMapper.writeValueAsString(pendingData);
        } catch (Exception e) {
            throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to serialize password reset data");
        }

        Long result = streamRedisTemplate.execute(
                new DefaultRedisScript<>(RedisLuaScripts.SET_PENDING_RESET_OTP, Long.class),
                List.of(lockKey),
                payloadJson,
                String.valueOf(passwordResetOtpExpiration)
        );

        if (result == null || result == 0) {
            return;
        }

        ForgotPasswordEvent event = passwordResetMapper.toForgotPasswordEvent(request, lockKey, otp);

        try {
            String eventJson = objectMapper.writeValueAsString(event);
            streamRedisTemplate.opsForStream().add(
                    StreamRecords.newRecord()
                            .in(passwordResetStreamKey)
                            .ofObject(eventJson)
                            .withId(RecordId.autoGenerate())
            );
        } catch (Exception e) {
            throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to publish password reset event");
        }
    }

    /**
     * Validates a password-reset OTP, deletes the Redis lock for single-use enforcement,
     * and returns a short-lived password-reset JWT.
     */
    @Override
    public VerifyOtpResponse verifyOtpForPasswordReset(String email, String otpCode) {
        String lockKey = passwordResetEmailLockPrefix + email;
        Object payloadObj = streamRedisTemplate.opsForValue().get(lockKey);

        if (payloadObj == null) {
            throw new CustomException(HttpStatus.BAD_REQUEST, "OTP expired or not found");
        }

        PendingPasswordResetData pendingData;
        try {
            pendingData = objectMapper.readValue(payloadObj.toString(), PendingPasswordResetData.class);
        } catch (Exception e) {
            throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to parse cached reset data");
        }

        if (!pendingData.getOtpCode().equals(otpCode)) {
            throw new CustomException(HttpStatus.BAD_REQUEST, "Invalid OTP code");
        }

        streamRedisTemplate.delete(lockKey);

        String resetToken = jwtTokenProvider.generatePasswordResetToken(email);
        return VerifyOtpResponse.builder().resetToken(resetToken).build();
    }

    /**
     * Validates the password-reset JWT, updates the user's password, blacklists the token
     * to enforce single-use, and revokes all existing refresh tokens for the user.
     */
    @Override
    @Transactional
    public void resetPassword(String resetToken, ResetPasswordRequest request) {
        if (tokenBlacklistService.isBlacklisted(resetToken)) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Token already used or revoked");
        }

        Claims claims;
        try {
            claims = jwtTokenProvider.extractAllClaims(resetToken);
        } catch (ExpiredJwtException e) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Password reset token has expired");
        } catch (Exception e) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Invalid password reset token");
        }

        String purpose = (String) claims.get("purpose");
        if (!"PASSWORD_RESET".equals(purpose)) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Invalid token type");
        }

        String email = claims.getSubject();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException(HttpStatus.NOT_FOUND, "User not found"));

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new CustomException(HttpStatus.BAD_REQUEST, "Passwords do not match");
        }

        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);

        long remainingTtl = claims.getExpiration().getTime() - System.currentTimeMillis();
        if (remainingTtl > 0) {
            tokenBlacklistService.blacklistToken(resetToken, remainingTtl);
        }

        if (Boolean.TRUE.equals(request.getRevokeOtherSessions())) {
            refreshTokenRepository.deleteByUserId(user.getUserId());
        }
    }

    // --- Private Helpers ---


    private TokenResponse generateTokenResponse(User user, ClientApp clientApp, ClientMetadata metadata) {
        String clientIdStr = clientApp != null ? clientApp.getClientId().toString() : null;
        JwtPayload jwtPayload = userMapper.toJwtPayload(user, clientIdStr);
        String accessToken = jwtTokenProvider.generateAccessToken(jwtPayload);

        String refreshTokenRaw = generateSecureToken();
        String refreshTokenHash = hashToken(refreshTokenRaw);

        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setUserId(user.getUserId());
        refreshTokenEntity.setClientId(clientApp != null ? clientApp.getClientId() : null);
        refreshTokenEntity.setTokenHash(refreshTokenHash);
        refreshTokenEntity.setExpiredAt(LocalDateTime.now().plusSeconds(refreshExpiration / 1000));
        refreshTokenEntity.setIsRevoked(false);

        // Capture device information from metadata
        if (metadata != null) {
            refreshTokenEntity.setDeviceId(metadata.getDeviceId());
            refreshTokenEntity.setDeviceName(metadata.getDeviceName());
            refreshTokenEntity.setIpAddress(metadata.getIpAddress());
            refreshTokenEntity.setUserAgent(metadata.getUserAgent());
        }
        refreshTokenEntity.setLastUsedAt(LocalDateTime.now());

        refreshTokenRepository.save(refreshTokenEntity);

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenRaw)
                .tokenType("Bearer")
                .expiredIn(refreshExpiration)
                .build();
    }

    private String generateSecureToken() {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().withLowerCase().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "SHA-256 algorithm not found");
        }
    }
}
