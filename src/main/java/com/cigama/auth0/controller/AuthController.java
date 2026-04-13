package com.cigama.auth0.controller;

import com.cigama.auth0.controller.doc.AuthApi;
import com.cigama.auth0.dto.request.*;
import com.cigama.auth0.dto.response.BaseResponse;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.dto.response.VerifyOtpResponse;
import com.cigama.auth0.service.AuthService;
import com.cigama.auth0.util.RequestUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/auth")
public class AuthController implements AuthApi {

    // --- Variables ---

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // --- Public Endpoints ---


    @Override
    @PostMapping("/register")
    public ResponseEntity<BaseResponse<Void>> register(
            @Valid @RequestBody RegisterRequest request,
            @RequestHeader(value = "X-API-Key", required = false) String apiKey
    ) {
        authService.register(request, apiKey);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(
                new BaseResponse<>(HttpStatus.ACCEPTED.value(), "Registration initialized. Please verify your OTP.", null)
        );
    }

    @Override
    @PostMapping("/verify-otp")
    public ResponseEntity<BaseResponse<?>> verifyOtp(
            @Valid @RequestBody VerifyOtpRequest request
    ) {
        if (request.getPurpose() == OtpPurpose.REGISTER) {
            authService.verifyOtp(request.getEmail(), request.getOtpCode());
            return ResponseEntity.ok(
                    new BaseResponse<>(HttpStatus.OK.value(), "OTP verified successfully. Please proceed to login.", null)
            );
        }
        if (request.getPurpose() == OtpPurpose.FORGOT_PASSWORD) {
            VerifyOtpResponse result = authService.verifyOtpForPasswordReset(request.getEmail(), request.getOtpCode());
            return ResponseEntity.ok(
                    new BaseResponse<>(HttpStatus.OK.value(), "OTP verified. Use the reset token to set your new password.", result)
            );
        }
        return ResponseEntity.badRequest().body(
                new BaseResponse<>(HttpStatus.BAD_REQUEST.value(), "Unsupported OTP purpose", null)
        );
    }

    @Override
    @PostMapping("/login")
    public ResponseEntity<BaseResponse<TokenResponse>> login(
            @Valid @RequestBody LoginRequest request,
            @RequestHeader(value = "X-API-Key", required = false) String apiKey,
            HttpServletRequest servletRequest
    ) {
        ClientMetadata metadata = RequestUtils.extractMetadata(servletRequest, request);
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
        ClientMetadata metadata = RequestUtils.extractMetadata(servletRequest, null);
        TokenResponse response = authService.refresh(request.getRefreshToken(), metadata);
        return ResponseEntity.ok(
                new BaseResponse<>(HttpStatus.OK.value(), "Token refreshed successfully", response)
        );
    }

    @Override
    @PostMapping("/logout")
    public ResponseEntity<BaseResponse<Void>> logout(
            @RequestHeader("Authorization") String bearerToken,
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        String accessToken = bearerToken.substring(7);
        authService.logout(accessToken, request.getRefreshToken());
        return ResponseEntity.ok(
                new BaseResponse<>(HttpStatus.OK.value(), "Logged out successfully", null)
        );
    }

    // --- Password Reset ---

    @Override
    @PostMapping("/forgot-password")
    public ResponseEntity<BaseResponse<Void>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request
    ) {
        authService.forgotPassword(request);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(
                new BaseResponse<>(HttpStatus.ACCEPTED.value(), "If this email is registered, you will receive a password reset OTP.", null)
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
                new BaseResponse<>(HttpStatus.OK.value(), "Password reset successfully. Please log in again.", null)
        );
    }
}
