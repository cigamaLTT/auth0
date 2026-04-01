package com.cigama.auth0.controller;

import com.cigama.auth0.dto.request.LoginRequest;
import com.cigama.auth0.dto.request.RefreshTokenRequest;
import com.cigama.auth0.dto.request.RegisterRequest;
import com.cigama.auth0.dto.response.BaseResponse;
import com.cigama.auth0.dto.response.TokenResponse;
import com.cigama.auth0.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    // --- Variables ---

    private final AuthService authService;

    // --- Public Endpoints ---

    @PostMapping("/register")
    public ResponseEntity<BaseResponse<Void>> register(
            @Valid @RequestBody RegisterRequest request,
            @RequestHeader(value = "X-API-Key", required = false) String apiKey
    ) {
        authService.register(request, apiKey);
        return ResponseEntity.status(HttpStatus.CREATED).body(
                BaseResponse.<Void>builder()
                        .status(HttpStatus.CREATED.value())
                        .message("User registered successfully")
                        .build()
        );
    }

    @PostMapping("/login")
    public ResponseEntity<BaseResponse<TokenResponse>> login(
            @Valid @RequestBody LoginRequest request,
            @RequestHeader(value = "X-API-Key", required = false) String apiKey
    ) {
        TokenResponse response = authService.login(request, apiKey);
        return ResponseEntity.ok(
                BaseResponse.<TokenResponse>builder()
                        .status(HttpStatus.OK.value())
                        .message("Login successful")
                        .data(response)
                        .build()
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<BaseResponse<TokenResponse>> refresh(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        TokenResponse response = authService.refresh(request.getRefreshToken());
        return ResponseEntity.ok(
                BaseResponse.<TokenResponse>builder()
                        .status(HttpStatus.OK.value())
                        .message("Token refreshed successfully")
                        .data(response)
                        .build()
        );
    }

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
}
