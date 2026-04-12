package com.cigama.auth0.redis;

import com.cigama.auth0.service.TokenBlacklistService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for TokenBlacklistServiceImpl.
 * Verifies key-value storage, TTL behavior, and blacklist lookup against a real Redis instance.
 */
class TokenBlacklistIntegrationTest extends BaseRedisIntegrationTest {

    @Autowired
    private TokenBlacklistService tokenBlacklistService;

    @Test
    void blacklistToken_ShouldMarkTokenAsBlacklisted() {
        String token = "valid.jwt.token";
        long ttlMillis = 60_000L; // 1 minute

        tokenBlacklistService.blacklistToken(token, ttlMillis);

        assertThat(tokenBlacklistService.isBlacklisted(token)).isTrue();
    }

    @Test
    void isBlacklisted_WhenTokenNotBlacklisted_ShouldReturnFalse() {
        assertThat(tokenBlacklistService.isBlacklisted("unknown.token")).isFalse();
    }

    @Test
    void blacklistToken_WhenTtlIsZeroOrNegative_ShouldNotStore() {
        // TTL <= 0 indicates token is already expired — no need to store
        tokenBlacklistService.blacklistToken("expired.token", 0L);
        tokenBlacklistService.blacklistToken("expired.token.negative", -1L);

        assertThat(tokenBlacklistService.isBlacklisted("expired.token")).isFalse();
        assertThat(tokenBlacklistService.isBlacklisted("expired.token.negative")).isFalse();
    }

    @Test
    void blacklistToken_DifferentTokens_ShouldBeIndependent() {
        tokenBlacklistService.blacklistToken("token.A", 60_000L);

        assertThat(tokenBlacklistService.isBlacklisted("token.A")).isTrue();
        assertThat(tokenBlacklistService.isBlacklisted("token.B")).isFalse();
    }
}
