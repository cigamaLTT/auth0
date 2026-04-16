package com.cigama.auth0.service.impl;

import com.cigama.auth0.dto.JwtPayload;
import com.cigama.auth0.dto.request.ClientMetadata;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.entity.ClientApp;
import com.cigama.auth0.entity.RefreshToken;
import com.cigama.auth0.entity.User;
import com.cigama.auth0.exception.CustomException;
import com.cigama.auth0.mapper.UserMapper;
import com.cigama.auth0.repository.RefreshTokenRepository;
import com.cigama.auth0.security.JwtTokenProvider;
import com.cigama.auth0.service.TokenService;
import com.cigama.auth0.util.Constants;
import com.cigama.auth0.util.HashUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class TokenServiceImpl implements TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceImpl.class);

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserMapper userMapper;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    public TokenServiceImpl(RefreshTokenRepository refreshTokenRepository,
                            JwtTokenProvider jwtTokenProvider,
                            UserMapper userMapper) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userMapper = userMapper;
    }

    @Override
    @Transactional
    public TokenResponse generateTokenResponse(User user, ClientApp clientApp, ClientMetadata metadata) {
        String clientIdStr = clientApp != null ? clientApp.getClientId().toString() : null;
        JwtPayload jwtPayload = userMapper.toJwtPayload(user, clientIdStr);
        String accessToken = jwtTokenProvider.generateAccessToken(jwtPayload);

        String refreshTokenRaw = generateSecureToken();
        String refreshTokenHash = HashUtils.hashValue(refreshTokenRaw);

        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setUserId(user.getUserId());
        refreshTokenEntity.setClientId(clientApp != null ? clientApp.getClientId() : null);
        refreshTokenEntity.setTokenHash(refreshTokenHash);
        refreshTokenEntity.setExpiredAt(LocalDateTime.now().plusSeconds(refreshExpiration / 1000));
        refreshTokenEntity.setIsRevoked(false);

        if (metadata != null) {
            refreshTokenEntity.setDeviceId(metadata.getDeviceId());
            refreshTokenEntity.setDeviceName(metadata.getDeviceName());
            refreshTokenEntity.setIpAddress(metadata.getIpAddress());
            refreshTokenEntity.setUserAgent(metadata.getUserAgent());
        }
        refreshTokenEntity.setLastUsedAt(LocalDateTime.now());

        refreshTokenRepository.save(refreshTokenEntity);

        return new TokenResponse(accessToken, refreshTokenRaw, Constants.BEARER_PREFIX.trim(), refreshExpiration);
    }

    @Override
    @Transactional
    public void revokeTokens(UUID userId, UUID deviceId) {
        refreshTokenRepository.findByUserIdAndDeviceId(userId, deviceId)
                .ifPresent(token -> {
                    token.setIsRevoked(true);
                    refreshTokenRepository.save(token);
                    log.info("Revoked refresh token for user {} on device {}", userId, deviceId);
                });
    }

    @Override
    @Transactional
    public void revokeAllTokens(UUID userId) {
        refreshTokenRepository.deleteByUserId(userId);
    }

    private String generateSecureToken() {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}
