package com.cigama.auth0.dto.response;

import jakarta.validation.constraints.NotBlank;

public record TokenResponse(
    String accessToken,
    String refreshToken,
    String tokenType,
    Long expiredIn
) {}
