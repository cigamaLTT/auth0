package com.cigama.auth0.dto.request;

import com.cigama.auth0.validation.ConfigurableLength;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class ResetPasswordRequest {
    @NotBlank(message = "Password is required")
    @ConfigurableLength(minKey = "app.policy.password-min-length")
    @Pattern(
            regexp = "^(?=.*[A-Z]).+$",
            message = "Password must contain at least 1 uppercase letter"
    )
    private String password;

    @NotBlank(message = "Password is required")
    @ConfigurableLength(minKey = "app.policy.password-min-length")
    @Pattern(
            regexp = "^(?=.*[A-Z]).+$",
            message = "Password must contain at least 1 uppercase letter"
    )
    private String confirmPassword;

    private Boolean revokeOtherSessions = true;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }

    public Boolean getRevokeOtherSessions() {
        return revokeOtherSessions;
    }

    public void setRevokeOtherSessions(Boolean revokeOtherSessions) {
        this.revokeOtherSessions = revokeOtherSessions;
    }
}
