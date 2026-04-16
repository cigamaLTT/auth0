package com.cigama.auth0.config;

import com.cigama.auth0.event.listener.RedisStreamSubscriber;
import org.springframework.context.annotation.Lazy;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.RedisSystemException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Component
public class RedisStreamInitializer {

    private static final Logger log = LoggerFactory.getLogger(RedisStreamInitializer.class);

    private final @Lazy RedisTemplate<String, Object> streamRedisTemplate;
    private final List<RedisStreamSubscriber> subscribers;

    public RedisStreamInitializer(@Lazy RedisTemplate<String, Object> streamRedisTemplate,
            List<RedisStreamSubscriber> subscribers) {
        this.streamRedisTemplate = streamRedisTemplate;
        this.subscribers = subscribers;
    }

    @PostConstruct
    public void init() {
        log.info("Initializing Redis Stream Consumer Groups via auto-discovery...");
        subscribers.forEach(subscriber -> {
            initGroup(subscriber.getStreamKey(), subscriber.getGroupName());
        });
    }

    private void initGroup(String streamKey, String groupName) {
        try {
            streamRedisTemplate.opsForStream().createGroup(streamKey, groupName);
            log.info("Created Consumer Group: {} for stream: {}", groupName, streamKey);
        } catch (RedisSystemException e) {
            if (e.getRootCause() != null && e.getRootCause().getMessage().contains("BUSYGROUP")) {
                log.debug("Consumer Group: {} already exists for stream: {}", groupName, streamKey);
            } else {
                try {
                    streamRedisTemplate.opsForStream().add(streamKey, Collections.singletonMap("_init", "true"));
                    streamRedisTemplate.opsForStream().createGroup(streamKey, groupName);
                    log.info("Initialized stream and created Consumer Group: {} for stream: {}", groupName, streamKey);
                } catch (Exception ignored) {
                }
            }
        } catch (Exception e) {
            log.error("Failed to initialize Consumer Group: {} for stream: {}: {}", groupName, streamKey,
                    e.getMessage());
        }
    }
}
