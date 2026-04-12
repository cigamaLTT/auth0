package com.cigama.auth0.redis;

import com.cigama.auth0.dto.cache.PendingUserData;
import com.cigama.auth0.event.dto.PendingRegistrationEvent;
import com.cigama.auth0.util.RedisLuaScripts;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.stream.ObjectRecord;
import org.springframework.data.redis.connection.stream.StreamOffset;
import org.springframework.data.redis.connection.stream.StreamRecords;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import tools.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for Redis Stream operations in the registration pipeline.
 *
 * Verifies:
 * - PendingUserData (with LocalDate) serializes/deserializes correctly via JSON.
 * - PendingRegistrationEvent can be published to and read from a Redis Stream.
 * - The full "register → cache + event" pipeline produces correct data in Redis.
 */
class RegistrationStreamIntegrationTest extends BaseRedisIntegrationTest {

    private static final String STREAM_KEY = "auth:registration:stream";
    private static final String EMAIL_KEY = "auth:lock:email:test@example.com";
    private static final String USERNAME_KEY = "auth:lock:username:testuser";

    @Autowired
    private ObjectMapper objectMapper;

    // --- Serialization Tests ---

    @Test
    void pendingUserData_WithLocalDate_ShouldSerializeAsIsoString() throws Exception {
        PendingUserData data = PendingUserData.builder()
                .email("test@example.com")
                .username("testuser")
                .password("hashed")
                .firstName("Test")
                .lastName("User")
                .dateOfBirth(LocalDate.of(1995, 12, 12))
                .otpCode("123456")
                .build();

        String json = objectMapper.writeValueAsString(data);

        // Must be "1995-12-12" not [1995, 12, 12]
        assertThat(json).contains("\"1995-12-12\"");
        assertThat(json).doesNotContain("[1995");

        // Must round-trip correctly
        PendingUserData deserialized = objectMapper.readValue(json, PendingUserData.class);
        assertThat(deserialized.getDateOfBirth()).isEqualTo(LocalDate.of(1995, 12, 12));
    }

    // --- Lua Script + JSON Round-Trip Test ---

    @Test
    void luaScript_WhenPendingUserDataStored_ShouldDeserializeCorrectly() throws Exception {
        PendingUserData original = PendingUserData.builder()
                .email("test@example.com")
                .username("testuser")
                .password("hashed")
                .otpCode("654321")
                .dateOfBirth(LocalDate.of(1990, 5, 20))
                .build();

        String payload = objectMapper.writeValueAsString(original);

        streamRedisTemplate.execute(
                new DefaultRedisScript<>(RedisLuaScripts.SET_PENDING_USER, Long.class),
                List.of(EMAIL_KEY, USERNAME_KEY),
                payload, "900"
        );

        // Read back from Redis and deserialize
        Object stored = streamRedisTemplate.opsForValue().get(EMAIL_KEY);
        assertThat(stored).isNotNull();

        PendingUserData recovered = objectMapper.readValue(stored.toString(), PendingUserData.class);
        assertThat(recovered.getEmail()).isEqualTo("test@example.com");
        assertThat(recovered.getOtpCode()).isEqualTo("654321");
        assertThat(recovered.getDateOfBirth()).isEqualTo(LocalDate.of(1990, 5, 20));
    }

    // --- Stream Publish/Consume Tests ---

    @Test
    void streamAdd_ShouldPublishEventToStream() throws Exception {
        PendingRegistrationEvent event = PendingRegistrationEvent.builder()
                .email("test@example.com")
                .username("testuser")
                .registrationId(EMAIL_KEY)
                .otpCode("111222")
                .build();

        String eventJson = objectMapper.writeValueAsString(event);

        streamRedisTemplate.opsForStream().add(
                StreamRecords.newRecord()
                        .in(STREAM_KEY)
                        .ofObject(eventJson)
        );

        List<ObjectRecord<String, String>> messages =
                streamRedisTemplate.opsForStream().read(
                        String.class,
                        StreamOffset.fromStart(STREAM_KEY)
                );

        assertThat(messages).hasSize(1);
        PendingRegistrationEvent recovered = objectMapper.readValue(messages.get(0).getValue(), PendingRegistrationEvent.class);
        assertThat(recovered.getEmail()).isEqualTo("test@example.com");
        assertThat(recovered.getOtpCode()).isEqualTo("111222");
    }

    @Test
    void streamAdd_MultipleEvents_ShouldMaintainOrder() throws Exception {
        for (int i = 1; i <= 3; i++) {
            PendingRegistrationEvent event = PendingRegistrationEvent.builder()
                    .email("user" + i + "@example.com")
                    .username("user" + i)
                    .registrationId("auth:lock:email:user" + i)
                    .otpCode("00000" + i)
                    .build();
            
            String eventJson = objectMapper.writeValueAsString(event);
            
            streamRedisTemplate.opsForStream().add(
                    StreamRecords.newRecord().in(STREAM_KEY).ofObject(eventJson)
            );
        }

        List<ObjectRecord<String, String>> messages =
                streamRedisTemplate.opsForStream().read(
                        String.class,
                        StreamOffset.fromStart(STREAM_KEY)
                );

        assertThat(messages).hasSize(3);
        PendingRegistrationEvent first = objectMapper.readValue(messages.get(0).getValue(), PendingRegistrationEvent.class);
        PendingRegistrationEvent last = objectMapper.readValue(messages.get(2).getValue(), PendingRegistrationEvent.class);
        assertThat(first.getEmail()).isEqualTo("user1@example.com");
        assertThat(last.getEmail()).isEqualTo("user3@example.com");
    }
}
