package com.cigama.auth0.dto.request;

import com.cigama.auth0.validation.ConfigurableLength;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

import java.util.UUID;

public record LoginRequest(
    @NotBlank(message = "Email or Username is required")
    String emailOrUsername,

    @NotBlank(message = "Password is required")
    @ConfigurableLength(minKey = "app.policy.password-min-length")
    @Pattern(
            regexp = "^(?=.*[A-Z]).+$",
            message = "Password must contain at least 1 uppercase letter"
    )
    String password,

    UUID deviceId,

    String deviceName
) {}
