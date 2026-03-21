package com.cigama.auth0.dto.response;

import com.cigama.auth0.entity.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class UserProfileResponse {

    private String userId;

    private String email;

    private Role role;

    private String firstName;

    private String lastName;

}
