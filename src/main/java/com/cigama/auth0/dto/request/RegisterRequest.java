package com.cigama.auth0.dto.request;


import com.cigama.auth0.validation.ConfigurableLength;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;

@Getter
@Setter
public class RegisterRequest {

    ///  -- Credentials --

    @Email(message = "Invalid Email format")
    @NotBlank(message = "Email is required")
    private String email;

    @Pattern(regexp = "\\d{10}", message = "Invalid Phone number")
    private String phoneNumber;

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


    ///  -- Identity --

    @NotBlank(message = "First Name is required")
    private String firstName;

    @NotBlank(message = "Last Name is required")
    private String lastName;

    @NotBlank(message = "Username is required")
    @ConfigurableLength(
            minKey = "app.policy.username-min-length",
            maxKey = "app.policy.username-max-length"
    )
    private String username;


    ///  -- Meta Data --

    @DateTimeFormat
    @Past
    private LocalDate dateOfBirth;

}
