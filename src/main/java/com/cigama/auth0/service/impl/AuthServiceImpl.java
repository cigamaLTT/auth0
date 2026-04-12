package com.cigama.auth0.service.impl;

import com.cigama.auth0.dto.JwtPayload;
import com.cigama.auth0.dto.request.LoginRequest;
import com.cigama.auth0.dto.request.RegisterRequest;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.entity.ClientApp;
import com.cigama.auth0.entity.RefreshToken;
import com.cigama.auth0.entity.Role;
import com.cigama.auth0.entity.User;
import com.cigama.auth0.mapper.UserMapper;
import com.cigama.auth0.mapper.RegistrationMapper;
import com.cigama.auth0.repository.RefreshTokenRepository;
import com.cigama.auth0.repository.UserRepository;
import com.cigama.auth0.repository.ClientAppRepository;
import com.cigama.auth0.security.JwtTokenProvider;
import com.cigama.auth0.service.AuthService;
import com.cigama.auth0.service.TokenBlacklistService;
import com.cigama.auth0.service.ValidationService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.cigama.auth0.config.RedisStreamConfig;
import com.cigama.auth0.dto.cache.PendingUserData;
import com.cigama.auth0.event.dto.PendingRegistrationEvent;
import com.cigama.auth0.util.RedisLuaScripts;
import org.springframework.data.redis.connection.stream.RecordId;
import org.springframework.data.redis.connection.stream.StreamRecords;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
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
            throw new RuntimeException("Failed to serialize pending user data", e);
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
            throw new RuntimeException("Email or Username is already taken.");
        }
        
        PendingRegistrationEvent event = registrationMapper.toRegistrationEvent(request, emailLockKey, generatedOtp);
                
        streamRedisTemplate.opsForStream().add(
                StreamRecords.newRecord()
                        .in(registrationStreamKey)
                        .ofObject(event)
                        .withId(RecordId.autoGenerate())
        );
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
            throw new RuntimeException("OTP expired or invalid.");
        }
        
        PendingUserData pendingData;
        try {
            pendingData = objectMapper.readValue(payloadObj.toString(), PendingUserData.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse cached user data", e);
        }
        
        if (!pendingData.getOtpCode().equals(otpCode)) {
            throw new RuntimeException("Invalid OTP code.");
        }
        
        User user = registrationMapper.pendingToUser(pendingData);
        user.setRole(Role.UNAUTHORIZED_USER);
        user.setIsAuthorized(true);
        
        if (pendingData.getClientId() != null) {
            ClientApp clientApp = clientAppRepository.findById(java.util.UUID.fromString(pendingData.getClientId())).orElse(null);
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
    public TokenResponse login(LoginRequest request, String apiKey) {
        User user = validationService.validateLogin(request);
        ClientApp clientApp = validationService.validateApiKey(apiKey);

        if (clientApp != null) {
            if (user.getClientApps() == null) {
                user.setClientApps(new HashSet<>());
            }
            if (user.getClientApps().add(clientApp)) {
                userRepository.save(user);
            }
        }

        return generateTokenResponse(user, clientApp);
    }

    /**
     * Validates the raw refresh token, marks it as revoked, and issues a new token pair.
     */
    @Override
    @Transactional
    public TokenResponse refresh(String refreshTokenRaw) {
        RefreshToken oldToken = validationService.validateRefreshToken(refreshTokenRaw);

        User user = userRepository.findById(oldToken.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found from valid refresh token"));

        if (!oldToken.getIsRevoked()) {
            oldToken.setIsRevoked(true);
            refreshTokenRepository.save(oldToken);
        }

        ClientApp clientApp = null;
        if (oldToken.getClientId() != null) {
            clientApp = clientAppRepository.findById(oldToken.getClientId()).orElse(null);
        }

        return generateTokenResponse(user, clientApp);
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

    // --- Private Helpers ---

    private TokenResponse generateTokenResponse(User user, ClientApp clientApp) {
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
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }
}
