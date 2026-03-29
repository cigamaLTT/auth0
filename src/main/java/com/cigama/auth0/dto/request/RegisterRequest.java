package com.cigama.auth0.dto.request;


import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;
import java.time.LocalDateTime;

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
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(
            regexp = "^(?=.*[A-Z]).+$",
            message = "Password must contain at least 1 uppercase letter"
    )
    private String password;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
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
    @Size(min = 4, max = 30, message = "Username's length should be at least 4 characters and at most 30 characters")
    private String username;


    ///  -- Meta Data --

    @DateTimeFormat
    @Past
    private LocalDate dateOfBirth;

    ///  -- Client Data --

    // This can be null

    private String clientName;

    private String clientId;

}
