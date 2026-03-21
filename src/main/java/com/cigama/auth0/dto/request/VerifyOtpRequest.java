package com.cigama.auth0.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VerifyOtpRequest {
    @Email(message = "Invalid Email format")
    @NotBlank(message = "Email is required")
    private String email;

    @Pattern(
            regexp = "^\\d{6}$"
    )
    private String otpCode;

    @NotNull
    private OtpPurpose purpose;
}
