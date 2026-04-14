package com.cigama.auth0.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ForgotPasswordRequest(
    @Email(message = "Invalid Email format")
    @NotBlank(message = "Email is required")
    String email
) {}
