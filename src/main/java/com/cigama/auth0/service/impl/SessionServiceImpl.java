package com.cigama.auth0.service.impl;

import com.cigama.auth0.dto.response.SessionResponse;
import com.cigama.auth0.entity.RefreshToken;
import com.cigama.auth0.exception.CustomException;
import com.cigama.auth0.mapper.UserMapper;
import com.cigama.auth0.repository.RefreshTokenRepository;
import com.cigama.auth0.service.SessionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
public class SessionServiceImpl implements SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionServiceImpl.class);

    // --- Variables ---

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserMapper userMapper;

    public SessionServiceImpl(RefreshTokenRepository refreshTokenRepository, UserMapper userMapper) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userMapper = userMapper;
    }

    // --- Methods ---

    @Override
    @Transactional(readOnly = true)
    public List<SessionResponse> getSessions(UUID userId) {
        log.debug("Fetching active sessions for user: {}", userId);
        return refreshTokenRepository.findByUserIdAndIsRevokedFalseAndExpiredAtAfter(userId, LocalDateTime.now())
                .stream()
                .map(userMapper::toSessionResponse)
                .toList();
    }

    @Override
    @Transactional
    public void revokeSession(UUID userId, UUID deviceId) {
        log.info("Revoking session for user: {} on device: {}", userId, deviceId);
        RefreshToken token = refreshTokenRepository.findByUserIdAndDeviceId(userId, deviceId)
                .orElseThrow(() -> new CustomException(HttpStatus.NOT_FOUND, "Session not found or already revoked"));

        token.setIsRevoked(true);
        refreshTokenRepository.save(token);
    }
}
