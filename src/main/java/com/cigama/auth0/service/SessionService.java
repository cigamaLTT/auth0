package com.cigama.auth0.service;

import com.cigama.auth0.dto.response.SessionResponse;

import java.util.List;
import java.util.UUID;

/**
 * Service for managing active user sessions (Refresh Tokens).
 */
public interface SessionService {
    /**
     * Retrieves all active sessions for a specific user.
     * @param userId The ID of the authenticated user.
     * @return A list of active session data.
     */
    List<SessionResponse> getSessions(UUID userId);

    /**
     * Revokes a specific session for a user by device ID.
     * @param userId The ID of the authenticated user.
     * @param deviceId The ID of the device/session to revoke.
     */
    void revokeSession(UUID userId, UUID deviceId);
}
