package com.cigama.auth0.repository;

import com.cigama.auth0.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    void deleteByUserId(UUID userId);

    List<RefreshToken> findByUserIdAndIsRevokedFalseAndExpiredAtAfter(UUID userId, LocalDateTime now);

    Optional<RefreshToken> findByUserIdAndDeviceId(UUID userId, UUID deviceId);
}