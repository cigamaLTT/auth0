package com.cigama.auth0.dto.response;

import com.cigama.auth0.entity.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record UserProfileResponse(
    String userId,
    String email,
    Role role,
    String firstName,
    String lastName
) {}
