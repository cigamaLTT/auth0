package com.cigama.auth0.controller.doc;

import com.cigama.auth0.dto.request.*;
import com.cigama.auth0.dto.response.BaseResponse;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.dto.response.VerifyOtpResponse;
import com.cigama.auth0.dto.userdetails.CustomUserDetails;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@Tag(name = "Authentication", description = "Endpoints for user registration, login, and token management")
public interface AuthApi {

    @Operation(summary = "Register a new user", description = "Initializes registration and sends an OTP via email.")
    ResponseEntity<BaseResponse<Void>> register(RegisterRequest request, String apiKey);

    @Operation(summary = "Verify OTP", description = "Verifies the OTP sent to the user's email. For REGISTER: completes registration. For FORGOT_PASSWORD: returns a password-reset token.")
    ResponseEntity<BaseResponse<?>> verifyOtp(VerifyOtpRequest request);

    @Operation(summary = "Login", description = "Authenticates a user and returns access and refresh tokens.")
    ResponseEntity<BaseResponse<TokenResponse>> login(
            LoginRequest request,
            String apiKey,
            @Parameter(hidden = true) HttpServletRequest servletRequest
    );

    @Operation(summary = "Refresh Token", description = "Generates a new access token using a valid refresh token.")
    ResponseEntity<BaseResponse<TokenResponse>> refresh(
            RefreshTokenRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest
    );

    @Operation(summary = "Logout", description = "Revokes the current session's refresh token and blacklists the access token.")
    @SecurityRequirement(name = "bearerAuth")
    ResponseEntity<BaseResponse<Void>> logout(String bearerToken);

    @Operation(summary = "Change Password", description = "Changes the password for the authenticated user.")
    @SecurityRequirement(name = "bearerAuth")
    ResponseEntity<BaseResponse<Void>> changePassword(
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserDetails userDetails,
            ChangePasswordRequest request
    );

    @Operation(summary = "Forgot Password", description = "Sends a password-reset OTP to the given email address if it is registered.")
    ResponseEntity<BaseResponse<Void>> forgotPassword(ForgotPasswordRequest request);

    @Operation(summary = "Reset Password", description = "Resets the user's password using the password-reset token obtained from OTP verification.")
    @SecurityRequirement(name = "bearerAuth")
    ResponseEntity<BaseResponse<Void>> resetPassword(String bearerToken, ResetPasswordRequest request);
}
