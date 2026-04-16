package com.cigama.auth0.event.listener;

import org.springframework.data.redis.connection.stream.ObjectRecord;
import org.springframework.data.redis.stream.StreamListener;

/**
 * Base interface for all Redis Stream listeners.
 * Provides metadata for automatic registration and grouping.
 */
public interface RedisStreamSubscriber extends StreamListener<String, ObjectRecord<String, String>> {
    
    /**
     * @return The Redis Stream key to subscribe to.
     */
    String getStreamKey();

    /**
     * @return The name of the Consumer Group for the subscription.
     */
    String getGroupName();
}
