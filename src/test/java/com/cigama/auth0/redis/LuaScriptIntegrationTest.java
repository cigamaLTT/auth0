package com.cigama.auth0.redis;

import com.cigama.auth0.util.RedisLuaScripts;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for the SET_PENDING_USER Lua script.
 *
 * These tests require a real Redis instance (via Testcontainers) because:
 * - Lua script execution cannot be meaningfully mocked.
 * - The atomic SET NX EX behavior must be verified against a real engine.
 * - TTL behavior is only observable on a real connection.
 */
class LuaScriptIntegrationTest extends BaseRedisIntegrationTest {

    private static final String EMAIL_KEY = "auth:lock:email:test@example.com";
    private static final String USERNAME_KEY = "auth:lock:username:testuser";
    private static final String PAYLOAD = "{\"email\":\"test@example.com\",\"username\":\"testuser\",\"dateOfBirth\":\"1995-12-12\"}";
    private static final String TTL = "900";

    // --- Success cases ---

    @Test
    void luaScript_WhenKeysAreFree_ShouldSetBothKeysAndReturnOne() {
        Long result = streamRedisTemplate.execute(
                new DefaultRedisScript<>(RedisLuaScripts.SET_PENDING_USER, Long.class),
                List.of(EMAIL_KEY, USERNAME_KEY),
                PAYLOAD, TTL
        );

        assertThat(result).isEqualTo(1L);
        assertThat(streamRedisTemplate.opsForValue().get(EMAIL_KEY)).isNotNull();
        assertThat(streamRedisTemplate.hasKey(USERNAME_KEY)).isTrue();
    }

    @Test
    void luaScript_WhenKeysAreFree_ShouldSetCorrectTTL() {
        streamRedisTemplate.execute(
                new DefaultRedisScript<>(RedisLuaScripts.SET_PENDING_USER, Long.class),
                List.of(EMAIL_KEY, USERNAME_KEY),
                PAYLOAD, TTL
        );

        Long emailTtl = streamRedisTemplate.getExpire(EMAIL_KEY, TimeUnit.SECONDS);
        Long usernameTtl = streamRedisTemplate.getExpire(USERNAME_KEY, TimeUnit.SECONDS);

        // TTL should be close to 900 seconds (allow 5s margin for test execution time)
        assertThat(emailTtl).isGreaterThan(894L);
        assertThat(usernameTtl).isGreaterThan(894L);
    }

    // --- Conflict cases ---

    @Test
    void luaScript_WhenEmailAlreadyLocked_ShouldReturnZeroAndNotSetUsername() {
        // Pre-lock the email key
        streamRedisTemplate.opsForValue().set(EMAIL_KEY, "EXISTING_PAYLOAD");

        Long result = streamRedisTemplate.execute(
                new DefaultRedisScript<>(RedisLuaScripts.SET_PENDING_USER, Long.class),
                List.of(EMAIL_KEY, USERNAME_KEY),
                PAYLOAD, TTL
        );

        assertThat(result).isEqualTo(0L);
        // Username key should NOT have been set (atomic rollback)
        assertThat(streamRedisTemplate.hasKey(USERNAME_KEY)).isFalse();
    }

    @Test
    void luaScript_WhenUsernameAlreadyLocked_ShouldReturnZeroAndNotLeakEmailKey() {
        // Pre-lock the username key
        streamRedisTemplate.opsForValue().set(USERNAME_KEY, "LOCKED");

        Long result = streamRedisTemplate.execute(
                new DefaultRedisScript<>(RedisLuaScripts.SET_PENDING_USER, Long.class),
                List.of(EMAIL_KEY, USERNAME_KEY),
                PAYLOAD, TTL
        );

        assertThat(result).isEqualTo(0L);
        // Email key should have been rolled back (no orphaned lock)
        assertThat(streamRedisTemplate.hasKey(EMAIL_KEY)).isFalse();
    }

    // --- Concurrency guard: second attempt on same email after success ---

    @Test
    void luaScript_WhenCalledTwiceWithSameEmail_ShouldReturnZeroOnSecondCall() {
        streamRedisTemplate.execute(
                new DefaultRedisScript<>(RedisLuaScripts.SET_PENDING_USER, Long.class),
                List.of(EMAIL_KEY, USERNAME_KEY),
                PAYLOAD, TTL
        );

        Long secondResult = streamRedisTemplate.execute(
                new DefaultRedisScript<>(RedisLuaScripts.SET_PENDING_USER, Long.class),
                List.of(EMAIL_KEY, USERNAME_KEY),
                PAYLOAD, TTL
        );

        assertThat(secondResult).isEqualTo(0L);
    }
}
