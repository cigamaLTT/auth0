package com.cigama.auth0.service.impl;

import com.cigama.auth0.dto.request.LoginRequest;
import com.cigama.auth0.dto.request.RegisterRequest;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.dto.userdetails.CustomUserDetails;
import com.cigama.auth0.entity.ClientApp;
import com.cigama.auth0.entity.RefreshToken;
import com.cigama.auth0.entity.Role;
import com.cigama.auth0.entity.User;
import com.cigama.auth0.repository.RefreshTokenRepository;
import com.cigama.auth0.repository.UserRepository;
import com.cigama.auth0.security.JwtTokenProvider;
import com.cigama.auth0.security.annotation.RegisterField;
import com.cigama.auth0.service.AuthService;
import com.cigama.auth0.service.ValidationService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    // --- Variables ---

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ValidationService validationService;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    private final List<FieldMapping> registerFieldMappings = new ArrayList<>();

    private record FieldMapping(Field sourceField, Field targetField) {}

    // --- Initialization ---

    @PostConstruct
    public void init() {
        Field[] sourceFields = RegisterRequest.class.getDeclaredFields();
        for (Field sourceField : sourceFields) {
            try {
                Field targetField = User.class.getDeclaredField(sourceField.getName());
                if (targetField.isAnnotationPresent(RegisterField.class)) {
                    sourceField.setAccessible(true);
                    targetField.setAccessible(true);
                    registerFieldMappings.add(new FieldMapping(sourceField, targetField));
                }
            } catch (NoSuchFieldException e) {
                // Ignore non-user entity fields
            }
        }
    }

    // --- Public Methods ---

    /**
     * Handles new user registration:
     * 1. Validates unique constraints and API Key client.
     * 2. Maps request data to Entity using cached reflection whitelist.
     * 3. Hashes password and persists user with their associated client.
     */
    @Override
    @Transactional
    public void register(RegisterRequest request, String apiKey) {
        ClientApp clientApp = validationService.validateRegistration(request, apiKey);
        User user = new User();
        
        for (FieldMapping mapping : registerFieldMappings) {
            try {
                Object value = mapping.sourceField().get(request);
                if (value != null) {
                    mapping.targetField().set(user, value);
                }
            } catch (IllegalAccessException e) {
                throw new RuntimeException("Register mapping failed", e);
            }
        }

        user.setRole(Role.UNAUTHORIZED_USER);
        user.setIsAuthorized(false);
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        if (clientApp != null) {
            if (user.getClientApps() == null) {
                user.setClientApps(new HashSet<>());
            }
            user.getClientApps().add(clientApp);
        }

        userRepository.save(user);
    }

    /**
     * Authenticates user and issues tokens:
     * 1. Verifies credentials and client-to-user links.
     * 2. Issues JWT Access Token with custom claims.
     * 3. Implements Refresh Token rotation by revoking old user tokens and generating a new hashed version.
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

        return generateTokenResponse(user);
    }

    /**
     * Rotates Refresh Token to maintain stateless authentication:
     * 1. Validates the provided raw token (including hash comparison and expiration).
     * 2. Fetches user with associated client apps (N+1 query protection via EntityGraph).
     * 3. Revokes the old token and issues a completely new access/refresh token pair.
     */
    @Override
    @Transactional
    public TokenResponse refresh(String refreshTokenRaw) {
        RefreshToken oldToken = validationService.validateRefreshToken(refreshTokenRaw);
        
        User user = userRepository.findById(oldToken.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found from valid refresh token"));

        refreshTokenRepository.delete(oldToken);

        return generateTokenResponse(user);
    }

    // --- Private Helpers ---

    /**
     * Core logic to generate a secure token response and persist rotated refresh tokens.
     */
    private TokenResponse generateTokenResponse(User user) {
        CustomUserDetails userDetails = CustomUserDetails.build(user);
        String accessToken = jwtTokenProvider.generateAccessToken(userDetails);

        String refreshTokenRaw = generateSecureToken();
        String refreshTokenHash = hashToken(refreshTokenRaw);

        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setUserId(user.getUserId());
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
