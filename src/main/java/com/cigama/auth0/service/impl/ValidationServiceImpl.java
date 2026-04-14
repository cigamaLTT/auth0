package com.cigama.auth0.service.impl;

import com.cigama.auth0.dto.request.LoginRequest;
import com.cigama.auth0.dto.request.RegisterRequest;
import com.cigama.auth0.entity.ClientApp;
import com.cigama.auth0.entity.RefreshToken;
import com.cigama.auth0.entity.User;
import com.cigama.auth0.exception.CustomException;
import com.cigama.auth0.repository.ClientAppRepository;
import com.cigama.auth0.repository.RefreshTokenRepository;
import com.cigama.auth0.repository.UserRepository;
import com.cigama.auth0.service.ValidationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.Optional;

@Service
public class ValidationServiceImpl implements ValidationService {

    private static final Logger log = LoggerFactory.getLogger(ValidationServiceImpl.class);

    // --- Variables ---

    private final UserRepository userRepository;
    private final ClientAppRepository clientAppRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;

    public ValidationServiceImpl(UserRepository userRepository,
                                 ClientAppRepository clientAppRepository,
                                 RefreshTokenRepository refreshTokenRepository,
                                 PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.clientAppRepository = clientAppRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Value("${jwt.refresh-grace-period}")
    private int refreshGracePeriodSeconds;

    // --- Public Methods ---

    /**
     * Validates registration data and optional API Key.
     */
    @Override
    public ClientApp validateRegistration(RegisterRequest request, String apiKey) {
        if (userRepository.existsByEmail(request.email())) {
            throw new CustomException(HttpStatus.CONFLICT, "Email is already in use.");
        }
        if (userRepository.existsByUsername(request.username())) {
            throw new CustomException(HttpStatus.CONFLICT, "Username is already in use.");
        }
        return validateApiKey(apiKey);
    }

    /**
     * Validates login credentials and fetches associated client apps.
     */
    @Override
    public User validateLogin(LoginRequest request) {
        User user = userRepository.findWithClientAppsByEmailOrUsername(request.emailOrUsername())
                .orElseThrow(() -> new CustomException(HttpStatus.UNAUTHORIZED, "Invalid username or password"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Invalid username or password");
        }
        return user;
    }

    /**
     * Verifies API Key hash against stored client tokens.
     */
    @Override
    public ClientApp validateApiKey(String apiKey) {
        if (apiKey == null || apiKey.isBlank()) {
            return null;
        }
        String hashedKey = hashValue(apiKey);
        log.info("Validating API Key: [{}], Hash: [{}]", apiKey, hashedKey);
        return clientAppRepository.findByClientToken(hashedKey)
                .orElseThrow(() -> {
                    log.error("Invalid API Key Hash: {}", hashedKey);
                    return new CustomException(HttpStatus.UNAUTHORIZED, "Invalid API Key");
                });
    }

    /**
     * Validates Refresh Token and handles rotation grace period (15s).
     */
    @Override
    @Transactional
    public RefreshToken validateRefreshToken(String token) {
        if (token == null || token.isBlank()) {
            throw new CustomException(HttpStatus.BAD_REQUEST, "Refresh token is required");
        }

        String hashedToken = hashValue(token);
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(hashedToken)
                .orElseThrow(() -> new CustomException(HttpStatus.UNAUTHORIZED, "Invalid refresh token"));

        if (refreshToken.getIsRevoked()) {
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime revokedAt = refreshToken.getUpdatedAt() != null ? 
                    refreshToken.getUpdatedAt() : refreshToken.getCreatedAt();

            if (revokedAt.plusSeconds(refreshGracePeriodSeconds).isBefore(now)) {
                log.warn("Token theft detected for user: {}", refreshToken.getUserId());
                refreshTokenRepository.deleteByUserId(refreshToken.getUserId());
                throw new CustomException(HttpStatus.UNAUTHORIZED, "Security alert: Potential token theft detected. All sessions have been revoked.");
            }
            log.info("Concurrent refresh detected for user: {}", refreshToken.getUserId());
        }

        if (refreshToken.getExpiredAt().isBefore(LocalDateTime.now())) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Refresh token has expired");
        }

        return refreshToken;
    }

    // --- Private Helpers ---

    private String hashValue(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().withLowerCase().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "SHA-256 algorithm not found");
        }
    }

    @Override
    public Optional<User> validateUserExistsByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}
