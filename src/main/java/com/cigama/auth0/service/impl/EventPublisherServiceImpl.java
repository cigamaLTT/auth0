package com.cigama.auth0.service.impl;

import com.cigama.auth0.service.EventPublisherService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.connection.stream.RecordId;
import org.springframework.data.redis.connection.stream.StreamRecords;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

@Service
public class EventPublisherServiceImpl implements EventPublisherService {

    private static final Logger log = LoggerFactory.getLogger(EventPublisherServiceImpl.class);

    private final RedisTemplate<String, Object> streamRedisTemplate;
    private final ObjectMapper objectMapper;

    public EventPublisherServiceImpl(
            @Qualifier("streamRedisTemplate") RedisTemplate<String, Object> streamRedisTemplate,
            ObjectMapper objectMapper) {
        this.streamRedisTemplate = streamRedisTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public void publishToStream(String streamKey, Object event) {
        try {
            String eventJson = objectMapper.writeValueAsString(event);
            streamRedisTemplate.opsForStream().add(
                    StreamRecords.newRecord()
                            .in(streamKey)
                            .ofObject(eventJson)
                            .withId(RecordId.autoGenerate())
            );
        } catch (Exception e) {
            log.error("Failed to publish event to {}: {}", streamKey, e.getMessage());
        }
    }
}
