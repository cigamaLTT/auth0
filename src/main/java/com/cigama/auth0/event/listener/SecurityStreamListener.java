package com.cigama.auth0.event.listener;

import com.cigama.auth0.event.dto.LoginTrackerEvent;
import com.cigama.auth0.event.dto.SuspiciousLoginEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Listener for Security-related events from Redis Streams.
 */
@Component
public class SecurityStreamListener {

    private static final Logger log = LoggerFactory.getLogger(SecurityStreamListener.class);

    public void onSuspiciousLogin(SuspiciousLoginEvent event) {
        log.warn("SUSPICIOUS LOGIN DETECTED: User={} IP={} Device={}", event.email(), event.ipAddress(), event.deviceId());
        // Handle security alerting logic
    }

    public void onLoginTracker(LoginTrackerEvent event) {
        log.info("Tracking login attempt: User={} Success={} IP={}", event.email(), event.success(), event.ipAddress());
        // Store in DB for stats
    }
}
