package com.cigama.auth0.dto.request;


import com.cigama.auth0.validation.ConfigurableLength;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;


@Getter
@Setter
public class LoginRequest {

    ///  -- Credentials --

    @NotBlank(message = "Email or Username is required")
    private String emailOrUsername;

    @NotBlank(message = "Password is required")
    @ConfigurableLength(minKey = "app.policy.password-min-length")
    @Pattern(
            regexp = "^(?=.*[A-Z]).+$",
            message = "Password must contain at least 1 uppercase letter"
    )
    private String password;

    private UUID deviceId;

    private String deviceName;

}
