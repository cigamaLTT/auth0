package com.cigama.auth0.controller;

import com.cigama.auth0.dto.request.SecuritySettingRequest;
import com.cigama.auth0.dto.request.VerifySecuritySettingRequest;
import com.cigama.auth0.dto.response.BaseResponse;
import com.cigama.auth0.dto.userdetails.CustomUserDetails;
import com.cigama.auth0.service.AuthService;
import com.cigama.auth0.service.SecuritySettingService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Controller for user-specific actions including security setting management.
 */
@RestController
@RequestMapping("/api/v1/user")
@Tag(name = "User Management", description = "Endpoints for managing user settings and profile.")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final AuthService authService;
    private final SecuritySettingService securitySettingService;

    public UserController(AuthService authService, SecuritySettingService securitySettingService) {
        this.authService = authService;
        this.securitySettingService = securitySettingService;
    }

    // --- Security Settings ---

    /**
     * Initiates a security setting update by sending an OTP.
     */
    @Operation(summary = "Request Security Setting Update", description = "Generates an OTP to verify changes to security settings.")
    @PostMapping("/security-settings/request-update")
    public ResponseEntity<BaseResponse<Void>> requestUpdate(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestBody SecuritySettingRequest request
    ) {
        UUID userId = UUID.fromString(userDetails.getUserId());
        securitySettingService.requestSecuritySettingUpdate(userId, request.settingName());
        
        return ResponseEntity.ok(
                new BaseResponse<>(HttpStatus.OK.value(), "OTP sent successfully to your registered email", null)
        );
    }

    /**
     * Verifies the OTP and applies the requested security setting change.
     */
    @Operation(summary = "Verify Security Setting Update", description = "Verifies the OTP and applies the boolean value to the security setting.")
    @PostMapping("/security-settings/verify-update")
    public ResponseEntity<BaseResponse<Void>> verifyUpdate(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestBody VerifySecuritySettingRequest request
    ) {
        UUID userId = UUID.fromString(userDetails.getUserId());
        securitySettingService.verifySecuritySettingUpdate(userId, request.settingName(), request.targetValue(), request.otpCode());
        
        return ResponseEntity.ok(
                new BaseResponse<>(HttpStatus.OK.value(), "Security setting updated successfully", null)
        );
    }
}
