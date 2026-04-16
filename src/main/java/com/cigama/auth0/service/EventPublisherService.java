package com.cigama.auth0.service;

public interface EventPublisherService {
    /**
     * Publishes an event to a specified Redis Stream.
     *
     * @param streamKey the Redis Stream key
     * @param event the event object to publish
     */
    void publishToStream(String streamKey, Object event);
}
