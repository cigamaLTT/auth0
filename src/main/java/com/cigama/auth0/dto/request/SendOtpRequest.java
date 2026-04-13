package com.cigama.auth0.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class SendOtpRequest {

    @NotNull
    private OtpPurpose purpose;

    @Email(message = "Invalid Email format")
    @NotBlank(message = "Email is required")
    private String email;

    public OtpPurpose getPurpose() {
        return purpose;
    }

    public void setPurpose(OtpPurpose purpose) {
        this.purpose = purpose;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

}
