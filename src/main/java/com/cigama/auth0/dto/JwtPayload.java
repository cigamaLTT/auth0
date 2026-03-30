/**
 * DTO carrying only the data that is safe to serialize into a JWT payload.
 * Acts as the contract between the authentication service and the token infrastructure.
 * Fields must remain a flat, JSON-serializable structure for reliable ObjectMapper conversion.
 */
package com.cigama.auth0.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtPayload {

    // --- Fields ---

    private String userId;
    private String username;
    private String firstName;
    private String lastName;
    private String role;
    private String clientId;
}
