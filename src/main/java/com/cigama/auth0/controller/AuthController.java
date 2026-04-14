package com.cigama.auth0.controller;

import com.cigama.auth0.controller.doc.AuthApi;
import com.cigama.auth0.dto.request.*;
import com.cigama.auth0.dto.response.BaseResponse;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.dto.response.VerifyOtpResponse;
import com.cigama.auth0.dto.userdetails.CustomUserDetails;
import com.cigama.auth0.exception.CustomException;
import com.cigama.auth0.service.AuthService;
import com.cigama.auth0.service.SessionService;
import com.cigama.auth0.service.ValidationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;
import java.util.List;

@RestController
@RequestMapping("/api/auth")
public class AuthController implements AuthApi {

    // --- Fields ---

    private final AuthService authService;
    private final ValidationService validationService;
    private final SessionService sessionService;

    public AuthController(AuthService authService,
                          ValidationService validationService,
                          SessionService sessionService) {
        this.authService = authService;
        this.validationService = validationService;
        this.sessionService = sessionService;
    }

    // --- Public Methods ---

    @Override
    @PostMapping("/register")
    public ResponseEntity<BaseResponse<Void>> register(
            @Valid @RequestBody RegisterRequest request,
            @RequestHeader("X-Api-Key") String apiKey
    ) {
        authService.register(request, apiKey);
        return ResponseEntity.ok(
                new BaseResponse<>(HttpStatus.OK.value(), "OTP sent to your email", null)
        );
    }

    @Override
    @PostMapping("/verify-otp")
    public ResponseEntity<BaseResponse<?>> verifyOtp(@Valid @RequestBody VerifyOtpRequest request) {
        if (OtpPurpose.REGISTER.equals(request.purpose())) {
            authService.verifyOtp(request.email(), request.otpCode());
            return ResponseEntity.ok(
                    new BaseResponse<>(HttpStatus.OK.value(), "Account verified successfully", null)
            );
        } else if (OtpPurpose.FORGOT_PASSWORD.equals(request.purpose())) {
            VerifyOtpResponse response = authService.verifyOtpForPasswordReset(request.email(), request.otpCode());
            return ResponseEntity.ok(
                    new BaseResponse<>(HttpStatus.OK.value(), "OTP verified successfully", response)
            );
        }
        throw new CustomException(HttpStatus.BAD_REQUEST, "Invalid OTP purpose");
    }

    @Override
    @PostMapping("/login")
    public ResponseEntity<BaseResponse<TokenResponse>> login(
            @Valid @RequestBody LoginRequest request,
            @RequestHeader("X-Api-Key") String apiKey,
            HttpServletRequest servletRequest
    ) {
        ClientMetadata metadata = new ClientMetadata(
                servletRequest.getRemoteAddr(),
                servletRequest.getHeader("User-Agent")
        );
        TokenResponse response = authService.login(request, apiKey, metadata);
        return ResponseEntity.ok(
                new BaseResponse<>(HttpStatus.OK.value(), "Login successful", response)
        );
    }

    @Override
    @PostMapping("/refresh")
    public ResponseEntity<BaseResponse<TokenResponse>> refresh(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest servletRequest
    ) {
        ClientMetadata metadata = new ClientMetadata(
                servletRequest.getRemoteAddr(),
                servletRequest.getHeader("User-Agent")
        );
        TokenResponse response = authService.refresh(request.refreshToken(), metadata);
        return ResponseEntity.ok(
                new BaseResponse<>(HttpStatus.OK.value(), "Token refreshed successfully", response)
        );
    }

    @Override
    @PostMapping("/logout")
    public ResponseEntity<BaseResponse<Void>> logout(
            @RequestHeader("Authorization") String bearerToken
    ) {
        String accessToken = bearerToken.substring(7);
        authService.logout(accessToken);
        return ResponseEntity.ok(
                new BaseResponse<>(HttpStatus.OK.value(), "Logged out successfully", null)
        );
    }

    @Override
    @PostMapping("/change-password")
    public ResponseEntity<BaseResponse<Void>> changePassword(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @Valid @RequestBody ChangePasswordRequest request
    ) {
        authService.changePassword(UUID.fromString(userDetails.getUserId()), request);
        return ResponseEntity.ok(
                new BaseResponse<>(HttpStatus.OK.value(), "Password changed successfully", null)
        );
    }

    // --- Password Reset ---

    @Override
    @PostMapping("/forgot-password")
    public ResponseEntity<BaseResponse<Void>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.forgotPassword(request);
        return ResponseEntity.ok(
                new BaseResponse<>(HttpStatus.OK.value(), "Password reset OTP sent to your email", null)
        );
    }

    @Override
    @PostMapping("/reset-password")
    public ResponseEntity<BaseResponse<Void>> resetPassword(
            @RequestHeader("Authorization") String bearerToken,
            @Valid @RequestBody ResetPasswordRequest request
    ) {
        String resetToken = bearerToken.substring(7);
        authService.resetPassword(resetToken, request);
        return ResponseEntity.ok(
                new BaseResponse<>(HttpStatus.OK.value(), "Password reset successfully", null)
        );
    }
}
