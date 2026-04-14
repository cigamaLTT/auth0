package com.cigama.auth0.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record VerifyOtpRequest(
    @Email(message = "Invalid Email format")
    @NotBlank(message = "Email is required")
    String email,

    @Pattern(regexp = "^\\d{6}$")
    String otpCode,

    @NotNull
    OtpPurpose purpose
) {}
