package com.cigama.auth0.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * Registry for Redis Lua Scripts to ensure atomicity for complex operations.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class RedisLuaScripts {

    /**
     * Script to atomically check if email/username exists in pending cache or DB,
     * and set the pending registration if available.
     * Prevents race conditions during simultaneous registrations.
     */
    public static final String SET_PENDING_USER = """
        -- KEYS[1]: email_lock_key, KEYS[2]: username_lock_key
        -- ARGV[1]: payload_json, ARGV[2]: ttl_seconds
        local email_set = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2])
        local user_set = redis.call('SET', KEYS[2], 'LOCKED', 'NX', 'EX', ARGV[2])
        
        if email_set and user_set then
            return 1
        else
            if email_set then redis.call('DEL', KEYS[1]) end
            if user_set then redis.call('DEL', KEYS[2]) end
            return 0
        end
        """;
}
