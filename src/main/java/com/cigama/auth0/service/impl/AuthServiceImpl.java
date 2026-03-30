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
import com.cigama.auth0.repository.RefreshTokenRepository;
import com.cigama.auth0.repository.UserRepository;
import com.cigama.auth0.security.JwtTokenProvider;
import com.cigama.auth0.service.AuthService;
import com.cigama.auth0.service.ValidationService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.HashSet;

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

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    // --- Public Methods ---

    /**
     * Validates unique constraints and API key, maps the request to a User entity via MapStruct,
     * then encodes the password and persists the user with optional client association.
     */
    @Override
    @Transactional
    public void register(RegisterRequest request, String apiKey) {
        ClientApp clientApp = validationService.validateRegistration(request, apiKey);
        User user = userMapper.toUser(request);

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

        return generateTokenResponse(user);
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

        return generateTokenResponse(user);
    }

    // --- Private Helpers ---

    private TokenResponse generateTokenResponse(User user) {
        JwtPayload jwtPayload = userMapper.toJwtPayload(user);
        String accessToken = jwtTokenProvider.generateAccessToken(jwtPayload);

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
