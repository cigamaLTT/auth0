package com.cigama.auth0.event.listener;

import com.cigama.auth0.event.dto.LoginTrackerEvent;
import com.cigama.auth0.event.dto.SuspiciousLoginEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Listener for Security-related events from Redis Streams.
 */
@Slf4j
@Component
public class SecurityStreamListener {

    public void onSuspiciousLogin(SuspiciousLoginEvent event) {
        log.warn("SUSPICIOUS LOGIN DETECTED: User={} IP={} Device={}", event.getEmail(), event.getIpAddress(), event.getDeviceId());
        // Handle security alerting logic
    }

    public void onLoginTracker(LoginTrackerEvent event) {
        log.info("Tracking login attempt: User={} Success={} IP={}", event.getEmail(), event.isSuccess(), event.getIpAddress());
        // Store in DB for stats
    }
}
