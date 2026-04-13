package com.cigama.auth0.dto.request;


import com.cigama.auth0.validation.ConfigurableLength;
import jakarta.validation.constraints.*;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;

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

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

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

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public LocalDate getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(LocalDate dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }
}
