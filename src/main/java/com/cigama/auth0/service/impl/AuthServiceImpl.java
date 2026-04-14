package com.cigama.auth0.service.impl;

import com.cigama.auth0.dto.cache.PendingUserData;
import com.cigama.auth0.dto.request.*;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.dto.response.VerifyOtpResponse;
import com.cigama.auth0.entity.ClientApp;
import com.cigama.auth0.entity.Role;
import com.cigama.auth0.entity.RefreshToken;
import com.cigama.auth0.entity.User;
import com.cigama.auth0.entity.UserSecuritySetting;
import com.cigama.auth0.event.dto.*;
import com.cigama.auth0.exception.CustomException;
import com.cigama.auth0.mapper.PasswordResetMapper;
import com.cigama.auth0.mapper.RegistrationMapper;
import com.cigama.auth0.repository.ClientAppRepository;
import com.cigama.auth0.repository.UserRepository;
import com.cigama.auth0.security.JwtTokenProvider;
import com.cigama.auth0.service.*;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.stream.RecordId;
import org.springframework.data.redis.connection.stream.StreamRecords;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.UUID;

/**
 * Service orchestrator for authentication and authorization logic.
 * Delegates specialized tasks to TokenService, SecuritySettingService, and OtpService.
 */
@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserRepository userRepository;
    private final ValidationService validationService;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RegistrationMapper registrationMapper;
    private final PasswordResetMapper passwordResetMapper;
    private final ClientAppRepository clientAppRepository;
    private final TokenBlacklistService tokenBlacklistService;
    private final RedisTemplate<String, Object> streamRedisTemplate;
    private final ObjectMapper objectMapper;
    private final TokenService tokenService;
    private final SecuritySettingService securitySettingService;
    private final OtpService otpService;

    public AuthServiceImpl(UserRepository userRepository,
                           ValidationService validationService,
                           PasswordEncoder passwordEncoder,
                           JwtTokenProvider jwtTokenProvider,
                           RegistrationMapper registrationMapper,
                           PasswordResetMapper passwordResetMapper,
                           ClientAppRepository clientAppRepository,
                           TokenBlacklistService tokenBlacklistService,
                           RedisTemplate<String, Object> streamRedisTemplate,
                           ObjectMapper objectMapper,
                           TokenService tokenService,
                           SecuritySettingService securitySettingService,
                           OtpService otpService) {
        this.userRepository = userRepository;
        this.validationService = validationService;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.registrationMapper = registrationMapper;
        this.passwordResetMapper = passwordResetMapper;
        this.clientAppRepository = clientAppRepository;
        this.tokenBlacklistService = tokenBlacklistService;
        this.streamRedisTemplate = streamRedisTemplate;
        this.objectMapper = objectMapper;
        this.tokenService = tokenService;
        this.securitySettingService = securitySettingService;
        this.otpService = otpService;
    }

    @Value("${app.registration.stream-key}")
    private String registrationStreamKey;

    @Value("${app.password-reset.stream-key}")
    private String passwordResetStreamKey;

    @Value("${jwt.password-reset-expiration}")
    private long passwordResetExpiration;

    @Value("${app.login.stream-key:auth:login-tracker:stream}")
    private String loginTrackerStreamKey;

    @Value("${app.security.stream-key:auth:security:stream}")
    private String securityStreamKey;

    // --- Core Authentication Methods ---

    @Override
    public void register(RegisterRequest request, String apiKey) {
        ClientApp clientApp = validationService.validateRegistration(request, apiKey);
        
        String generatedOtp = String.format("%06d", new SecureRandom().nextInt(999999));
        String encodedPassword = passwordEncoder.encode(request.password());
        String clientIdStr = clientApp != null ? clientApp.getClientId().toString() : null;
        
        PendingUserData pendingData = registrationMapper.toPendingUserData(request, encodedPassword, generatedOtp, clientIdStr);
        String savedOtp = otpService.generateAndSaveRegistrationOtp(pendingData);

        PendingRegistrationEvent event = registrationMapper.toRegistrationEvent(request, "auth:lock:email:" + request.email(), savedOtp);
        publishToStream(registrationStreamKey, event);
    }

    @Override
    @Transactional
    public void verifyOtp(String email, String otpCode) {
        PendingUserData pendingData = otpService.verifyRegistrationOtp(email, otpCode);
        
        User user = registrationMapper.pendingToUser(pendingData);
        user.setRole(Role.AUTHORIZED_USER);
        user.setIsAuthorized(true);
        user.setSecuritySetting(new UserSecuritySetting(user));
        
        if (pendingData.clientId() != null) {
            clientAppRepository.findById(UUID.fromString(pendingData.clientId())).ifPresent(clientApp -> {
                if (user.getClientApps() == null) user.setClientApps(new HashSet<>());
                user.getClientApps().add(clientApp);
            });
        }
        
        userRepository.save(user);
        publishToStream(registrationStreamKey, new RegistrationSuccessEvent(user.getEmail(), user.getUsername(), LocalDateTime.now()));
    }

    @Override
    @Transactional
    public TokenResponse login(LoginRequest request, String apiKey, ClientMetadata metadata) {
        String identifier = request.emailOrUsername();
        String lockoutKey = "auth:lockout:" + identifier;

        if (Boolean.TRUE.equals(streamRedisTemplate.hasKey(lockoutKey))) {
            publishLoginEvent(identifier, false, metadata, "Account is locked");
            throw new CustomException(HttpStatus.LOCKED, "Account is temporarily locked.");
        }

        ClientApp clientApp = (apiKey != null) ? validationService.validateApiKey(apiKey) : null;
        User user;
        try {
            user = validationService.validateLogin(request);
        } catch (CustomException e) {
            publishLoginEvent(identifier, false, metadata, e.getMessage());
            throw e;
        }

        streamRedisTemplate.delete("auth:failed_attempts:" + identifier);
        if (clientApp != null) {
            if (user.getClientApps() == null) user.setClientApps(new HashSet<>());
            if (user.getClientApps().add(clientApp)) userRepository.save(user);
        }

        TokenResponse response = tokenService.generateTokenResponse(user, clientApp, metadata);
        publishLoginEvent(identifier, true, metadata, null);
        return response;
    }

    @Override
    @Transactional
    public TokenResponse refresh(String refreshTokenRaw, ClientMetadata metadata) {
        RefreshToken oldToken = (RefreshToken) validationService.validateRefreshToken(refreshTokenRaw);
        User user = userRepository.findById(oldToken.getUserId())
                .orElseThrow(() -> new CustomException(HttpStatus.NOT_FOUND, "User not found"));

        TokenResponse response = tokenService.generateTokenResponse(user, null, metadata);
        oldToken.setIsRevoked(true);
        // refreshTokenRepository.save(oldToken); // Should be handled by TokenService
        return response;
    }

    @Override
    @Transactional
    public void logout(String accessToken) {
        Claims claims;
        try {
            claims = jwtTokenProvider.extractAllClaims(accessToken);
        } catch (Exception e) {
            return;
        }

        String userIdStr = claims.getSubject();
        String deviceIdStr = (String) claims.get("deviceId");

        if (userIdStr != null && deviceIdStr != null) {
            tokenService.revokeTokens(UUID.fromString(userIdStr), UUID.fromString(deviceIdStr));
        }

        long remainingTtl = claims.getExpiration().getTime() - System.currentTimeMillis();
        if (remainingTtl > 0) {
            tokenBlacklistService.blacklistToken(accessToken, remainingTtl);
        }
    }

    @Override
    public void forgotPassword(ForgotPasswordRequest request) {
        if (validationService.validateUserExistsByEmail(request.email()).isEmpty()) return;

        String otp = otpService.generateAndSavePasswordResetOtp(request.email());
        publishToStream(passwordResetStreamKey, passwordResetMapper.toForgotPasswordEvent(request, "auth:lock:reset:" + request.email(), otp));
    }

    @Override
    public VerifyOtpResponse verifyOtpForPasswordReset(String email, String otpCode) {
        otpService.verifyPasswordResetOtp(email, otpCode);
        String resetToken = jwtTokenProvider.generateActionToken(email, "PASSWORD_RESET", passwordResetExpiration);
        return new VerifyOtpResponse(resetToken);
    }

    @Override
    @Transactional
    public void resetPassword(String resetToken, ResetPasswordRequest request) {
        if (tokenBlacklistService.isBlacklisted(resetToken)) throw new CustomException(HttpStatus.UNAUTHORIZED, "Token already used");

        Claims claims;
        try {
            claims = jwtTokenProvider.extractAllClaims(resetToken);
        } catch (ExpiredJwtException e) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Token expired");
        } catch (Exception e) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Invalid token");
        }

        if (!"PASSWORD_RESET".equals(claims.get("purpose"))) throw new CustomException(HttpStatus.UNAUTHORIZED, "Invalid token purpose");

        String email = claims.getSubject();
        User user = userRepository.findByEmail(email).orElseThrow(() -> new CustomException(HttpStatus.NOT_FOUND, "User not found"));

        user.setPassword(passwordEncoder.encode(request.password()));
        userRepository.save(user);

        if (Boolean.TRUE.equals(request.logoutAllSessions())) tokenService.revokeAllTokens(user.getUserId());

        long remainingTtl = claims.getExpiration().getTime() - System.currentTimeMillis();
        if (remainingTtl > 0) tokenBlacklistService.blacklistToken(resetToken, remainingTtl);

        publishToStream(securityStreamKey, new PasswordResetSuccessEvent(email, "unknown", LocalDateTime.now()));
    }

    @Override
    @Transactional
    public void changePassword(UUID userId, ChangePasswordRequest request) {
        if (securitySettingService.isOtpRequired(userId, "REQUIRE_OTP_FOR_PASSWORD")) {
            throw new CustomException(HttpStatus.FORBIDDEN, "OTP verification required.");
        }

        User user = userRepository.findById(userId).orElseThrow(() -> new CustomException(HttpStatus.NOT_FOUND, "User not found"));

        if (!passwordEncoder.matches(request.oldPassword(), user.getPassword())) {
            throw new CustomException(HttpStatus.BAD_REQUEST, "Incorrect old password.");
        }

        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);

        if (Boolean.TRUE.equals(request.logoutAllSessions())) tokenService.revokeAllTokens(user.getUserId());

        publishToStream(securityStreamKey, new ChangePasswordSuccessEvent(user.getEmail(), "unknown", LocalDateTime.now()));
    }

    private void publishLoginEvent(String identifier, boolean success, ClientMetadata metadata, String reason) {
        LoginTrackerEvent event = new LoginTrackerEvent(
                identifier, success,
                metadata != null ? metadata.getIpAddress() : "unknown",
                (metadata != null && metadata.getDeviceId() != null) ? metadata.getDeviceId().toString() : "unknown",
                LocalDateTime.now(), reason
        );
        publishToStream(loginTrackerStreamKey, event);
    }

    private void publishToStream(String streamKey, Object event) {
        try {
            String eventJson = objectMapper.writeValueAsString(event);
            streamRedisTemplate.opsForStream().add(StreamRecords.newRecord().in(streamKey).ofObject(eventJson).withId(RecordId.autoGenerate()));
        } catch (Exception e) {
            log.error("Failed to publish event to {}: {}", streamKey, e.getMessage());
        }
    }
}
