package com.cigama.auth0.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SendOtpRequest {

    @NotNull
    private OtpPurpose purpose;

    @Email(message = "Invalid Email format")
    @NotBlank(message = "Email is required")
    private String email;

}
