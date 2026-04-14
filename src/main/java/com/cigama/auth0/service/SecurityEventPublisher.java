package com.cigama.auth0.service;

public interface SecurityEventPublisher {
    void publishAccountLockout(String email, String ipAddress, String reason);
}
