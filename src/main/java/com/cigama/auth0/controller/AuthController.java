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
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController implements AuthApi {

    // --- Variables ---

    private final AuthService authService;

    // --- Public Endpoints ---


    @Override
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

    @Override
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
                BaseResponse.<TokenResponse>builder()
                        .status(HttpStatus.OK.value())
                        .message("Login successful")
                        .data(response)
                        .build()
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
                BaseResponse.<TokenResponse>builder()
                        .status(HttpStatus.OK.value())
                        .message("Token refreshed successfully")
                        .data(response)
                        .build()
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
                BaseResponse.<Void>builder()
                        .status(HttpStatus.OK.value())
                        .message("Logged out successfully")
                        .build()
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
                BaseResponse.<Void>builder()
                        .status(HttpStatus.ACCEPTED.value())
                        .message("If this email is registered, you will receive a password reset OTP.")
                        .build()
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
                BaseResponse.<Void>builder()
                        .status(HttpStatus.OK.value())
                        .message("Password reset successfully. Please log in again.")
                        .build()
        );
    }
}
