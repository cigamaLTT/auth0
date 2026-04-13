package com.cigama.auth0.controller;

import com.cigama.auth0.dto.request.*;
import com.cigama.auth0.dto.response.BaseResponse;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.dto.response.VerifyOtpResponse;
import com.cigama.auth0.service.AuthService;
import com.cigama.auth0.util.RequestUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Endpoints for user registration, login, and token management")
public class AuthController {

    // --- Variables ---

    private final AuthService authService;

    // --- Public Endpoints ---


    @Operation(summary = "Register a new user", description = "Initializes registration and sends an OTP via email.")
    @PostMapping("/register")
    public ResponseEntity<BaseResponse<Void>> register(
            @Valid @RequestBody RegisterRequest request,
            @RequestHeader(value = "X-API-Key", required = false) String apiKey
    ) {
        authService.register(request, apiKey);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(
                BaseResponse.<Void>builder()
                        .status(HttpStatus.ACCEPTED.value())
                        .message("Registration initialized. Please verify your OTP.")
                        .build()
        );
    }

    @Operation(summary = "Verify OTP", description = "Verifies the OTP sent to the user's email. For REGISTER: completes registration. For FORGOT_PASSWORD: returns a password-reset token.")
    @PostMapping("/verify-otp")
    public ResponseEntity<BaseResponse<?>> verifyOtp(
            @Valid @RequestBody VerifyOtpRequest request
    ) {
        if (request.getPurpose() == OtpPurpose.REGISTER) {
            authService.verifyOtp(request.getEmail(), request.getOtpCode());
            return ResponseEntity.ok(
                    BaseResponse.<Void>builder()
                            .status(HttpStatus.OK.value())
                            .message("OTP verified successfully. Please proceed to login.")
                            .build()
            );
        }
        if (request.getPurpose() == OtpPurpose.FORGOT_PASSWORD) {
            VerifyOtpResponse result = authService.verifyOtpForPasswordReset(request.getEmail(), request.getOtpCode());
            return ResponseEntity.ok(
                    BaseResponse.<VerifyOtpResponse>builder()
                            .status(HttpStatus.OK.value())
                            .message("OTP verified. Use the reset token to set your new password.")
                            .data(result)
                            .build()
            );
        }
        return ResponseEntity.badRequest().body(
                BaseResponse.<Void>builder()
                        .status(HttpStatus.BAD_REQUEST.value())
                        .message("Unsupported OTP purpose")
                        .build()
        );
    }

    @Operation(summary = "Login", description = "Authenticates a user and returns access and refresh tokens.")
    @PostMapping("/login")
    public ResponseEntity<BaseResponse<TokenResponse>> login(
            @Valid @RequestBody LoginRequest request,
            @RequestHeader(value = "X-API-Key", required = false) String apiKey,
            HttpServletRequest servletRequest
    ) {
        ClientMetadata metadata = RequestUtils.extractMetadata(servletRequest, request);
        TokenResponse response = authService.login(request, apiKey, metadata);
        return ResponseEntity.ok(
                BaseResponse.<TokenResponse>builder()
                        .status(HttpStatus.OK.value())
                        .message("Login successful")
                        .data(response)
                        .build()
        );
    }

    @Operation(summary = "Refresh Token", description = "Generates a new access token using a valid refresh token.")
    @PostMapping("/refresh")
    public ResponseEntity<BaseResponse<TokenResponse>> refresh(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest servletRequest
    ) {
        ClientMetadata metadata = RequestUtils.extractMetadata(servletRequest, null);
        TokenResponse response = authService.refresh(request.getRefreshToken(), metadata);
        return ResponseEntity.ok(
                BaseResponse.<TokenResponse>builder()
                        .status(HttpStatus.OK.value())
                        .message("Token refreshed successfully")
                        .data(response)
                        .build()
        );
    }

    @Operation(summary = "Logout", description = "Revokes the given access and refresh tokens.")
    @SecurityRequirement(name = "bearerAuth")
    @PostMapping("/logout")
    public ResponseEntity<BaseResponse<Void>> logout(
            @RequestHeader("Authorization") String bearerToken,
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        String accessToken = bearerToken.substring(7);
        authService.logout(accessToken, request.getRefreshToken());
        return ResponseEntity.ok(
                BaseResponse.<Void>builder()
                        .status(HttpStatus.OK.value())
                        .message("Logged out successfully")
                        .build()
        );
    }

    // --- Password Reset ---

    @Operation(summary = "Forgot Password", description = "Sends a password-reset OTP to the given email address if it is registered.")
    @PostMapping("/forgot-password")
    public ResponseEntity<BaseResponse<Void>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request
    ) {
        authService.forgotPassword(request);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(
                BaseResponse.<Void>builder()
                        .status(HttpStatus.ACCEPTED.value())
                        .message("If this email is registered, you will receive a password reset OTP.")
                        .build()
        );
    }

    @Operation(summary = "Reset Password", description = "Resets the user's password using the password-reset token obtained from OTP verification.")
    @PostMapping("/reset-password")
    public ResponseEntity<BaseResponse<Void>> resetPassword(
            @RequestHeader("Authorization") String bearerToken,
            @Valid @RequestBody ResetPasswordRequest request
    ) {
        String resetToken = bearerToken.substring(7);
        authService.resetPassword(resetToken, request);
        return ResponseEntity.ok(
                BaseResponse.<Void>builder()
                        .status(HttpStatus.OK.value())
                        .message("Password reset successfully. Please log in again.")
                        .build()
        );
    }
}
