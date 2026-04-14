package com.cigama.auth0.event.dto;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Event triggered when a user registration is successfully verified.
 */
public record RegistrationSuccessEvent(
        String email,
        String username,
        LocalDateTime timestamp
) implements Serializable {}
