package com.cigama.auth0.redis;

import com.cigama.auth0.event.dto.PendingRegistrationEvent;
import org.junit.jupiter.api.AfterEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.data.redis.connection.stream.ObjectRecord;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.stream.StreamMessageListenerContainer;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;

/**
 * Base class for Redis integration tests using a shared Singleton container.
 * @MockitoBean suppresses the production listener to prevent conflicts during tests.
 */
@SpringBootTest
public abstract class BaseRedisIntegrationTest {

    // Singleton pattern: container is started once, reused across all subclasses
    static final GenericContainer<?> REDIS;

    static {
        REDIS = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);
        REDIS.start();
    }

    @DynamicPropertySource
    static void redisProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", REDIS::getFirstMappedPort);
        registry.add("spring.data.redis.password", () -> "");
    }

    // Suppress the production listener to avoid connection conflicts during tests
    @MockitoBean
    StreamMessageListenerContainer<String, ObjectRecord<String, PendingRegistrationEvent>> registrationStreamListenerContainer;

    @Autowired
    protected RedisTemplate<String, Object> streamRedisTemplate;

    /** Clear Redis state between tests. */
    @AfterEach
    void cleanRedis() {
        streamRedisTemplate.getConnectionFactory()
                .getConnection()
                .serverCommands()
                .flushAll();
    }
}
