package com.cigama.auth0.dto.request;

import com.cigama.auth0.validation.ConfigurableLength;
import com.cigama.auth0.validation.FieldsValueMatch;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

@FieldsValueMatch(
        field = "newPassword",
        fieldMatch = "confirmPassword",
        message = "New passwords do not match."
)
public record ChangePasswordRequest(
    @NotBlank(message = "Current password is required")
    String oldPassword,

    @NotBlank(message = "New password is required")
    @ConfigurableLength(minKey = "app.policy.password-min-length")
    @Pattern(
            regexp = "^(?=.*[A-Z]).+$",
            message = "New password must contain at least 1 uppercase letter"
    )
    String newPassword,

    @NotBlank(message = "Confirm password is required")
    String confirmPassword,

    Boolean logoutAllSessions
) {}
