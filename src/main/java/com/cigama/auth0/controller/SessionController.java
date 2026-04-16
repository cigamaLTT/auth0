package com.cigama.auth0.controller;

import com.cigama.auth0.dto.response.BaseResponse;
import com.cigama.auth0.dto.response.SessionResponse;
import com.cigama.auth0.dto.userdetails.CustomUserDetails;
import com.cigama.auth0.service.SessionService;
import com.cigama.auth0.util.SecurityUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/sessions")
@Tag(name = "Session Management", description = "Endpoints for managing active user sessions and devices.")
@SecurityRequirement(name = "bearerAuth")
public class SessionController {

    private final SessionService sessionService;

    public SessionController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @Operation(summary = "Get Active Sessions", description = "Retrieves a list of all active sessions/devices for the authenticated user.")
    @GetMapping
    public ResponseEntity<BaseResponse<List<SessionResponse>>> getSessions(
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        UUID userId = SecurityUtils.getUserIdAsUuid(userDetails);
        List<SessionResponse> sessions = sessionService.getSessions(userId);
        
        return ResponseEntity.ok(
                new BaseResponse<>(HttpStatus.OK.value(), "Active sessions retrieved successfully", sessions)
        );
    }

    @Operation(summary = "Revoke Session", description = "Revokes a specific session by its device ID.")
    @DeleteMapping("/{deviceId}")
    public ResponseEntity<BaseResponse<Void>> revokeSession(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @PathVariable UUID deviceId
    ) {
        UUID userId = SecurityUtils.getUserIdAsUuid(userDetails);
        sessionService.revokeSession(userId, deviceId);
        
        return ResponseEntity.ok(
                new BaseResponse<>(HttpStatus.OK.value(), "Session revoked successfully", null)
        );
    }
}
