package com.cigama.auth0.dto.request;

import com.cigama.auth0.validation.ConfigurableLength;
import com.cigama.auth0.validation.FieldsValueMatch;
import jakarta.validation.constraints.*;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;

@FieldsValueMatch(
        field = "password",
        fieldMatch = "confirmPassword",
        message = "Passwords do not match."
)
public record RegisterRequest(
    @Email(message = "Invalid Email format")
    @NotBlank(message = "Email is required")
    String email,

    @Pattern(regexp = "\\d{10}", message = "Invalid Phone number")
    String phoneNumber,

    @NotBlank(message = "Password is required")
    @ConfigurableLength(minKey = "app.policy.password-min-length")
    @Pattern(
            regexp = "^(?=.*[A-Z]).+$",
            message = "Password must contain at least 1 uppercase letter"
    )
    String password,

    @NotBlank(message = "Confirm password is required")
    String confirmPassword,

    @NotBlank(message = "First Name is required")
    String firstName,

    @NotBlank(message = "Last Name is required")
    String lastName,

    @NotBlank(message = "Username is required")
    @ConfigurableLength(
            minKey = "app.policy.username-min-length",
            maxKey = "app.policy.username-max-length"
    )
    String username,

    @DateTimeFormat
    @Past
    LocalDate dateOfBirth
) {}
