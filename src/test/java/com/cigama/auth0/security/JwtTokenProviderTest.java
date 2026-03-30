package com.cigama.auth0.security;

import com.cigama.auth0.dto.JwtPayload;
import tools.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenProviderTest {

    // --- Variables ---

    private JwtTokenProvider jwtTokenProvider;

    private final String RAW_SECRET = "RandomVeryLongSecretKeyForHmacSha256AlgorithmThatExceeds256Bits12345!@#";
    private final String VALID_BASE64_SECRET = Base64.getEncoder().encodeToString(RAW_SECRET.getBytes());
    private final long VALID_EXPIRATION = 3600000L;

    // --- Setup ---

    @BeforeEach
    void setUp() {
        jwtTokenProvider = new JwtTokenProvider(new ObjectMapper());
        ReflectionTestUtils.setField(jwtTokenProvider, "jwtSecret", VALID_BASE64_SECRET);
        ReflectionTestUtils.setField(jwtTokenProvider, "jwtExpiration", VALID_EXPIRATION);
        jwtTokenProvider.init();
    }

    // --- Helpers ---

    private JwtPayload generateRandomPayload(String role) {
        return JwtPayload.builder()
                .userId(UUID.randomUUID().toString())
                .username("user_" + UUID.randomUUID().toString().substring(0, 8))
                .firstName("Test")
                .lastName("User")
                .role(role)
                .build();
    }


    // --- Test Cases ---

    @Test
    void generateAccessToken_WithAdminRole_ProducesValidJwt() {
        JwtPayload payload = generateRandomPayload("ROLE_ADMIN");

        String token = jwtTokenProvider.generateAccessToken(payload);

        assertNotNull(token);
        assertFalse(token.isBlank());
        assertEquals(3, token.split("\\.").length);
    }

    @Test
    void generateAccessToken_WithAuthorizedUserRole_ProducesValidJwt() {
        JwtPayload payload = generateRandomPayload("ROLE_AUTHORIZED_USER");

        String token = jwtTokenProvider.generateAccessToken(payload);

        assertNotNull(token);
        assertEquals(3, token.split("\\.").length);
    }

    @Test
    void generateAccessToken_WithUnauthorizedUserRole_ProducesValidJwt() {
        JwtPayload payload = generateRandomPayload("ROLE_UNAUTHORIZED_USER");

        String token = jwtTokenProvider.generateAccessToken(payload);

        assertNotNull(token);
        assertEquals(3, token.split("\\.").length);
    }

    @Test
    void extractAllClaims_ClaimsMatchJwtPayloadFields() {
        JwtPayload payload = generateRandomPayload("ROLE_AUTHORIZED_USER");
        String token = jwtTokenProvider.generateAccessToken(payload);

        Claims claims = jwtTokenProvider.extractAllClaims(token);

        assertEquals(payload.getUserId(), claims.get("userId", String.class));
        assertEquals(payload.getUsername(), claims.get("username", String.class));
        assertEquals(payload.getFirstName(), claims.get("firstName", String.class));
        assertEquals(payload.getLastName(), claims.get("lastName", String.class));
        assertEquals(payload.getRole(), claims.get("role", String.class));
        assertEquals(payload.getUserId(), claims.getSubject());
    }

    @Test
    void generateAccessToken_WithNullClaimValues_ShouldNotCrash() {
        JwtPayload payloadWithNulls = JwtPayload.builder()
                .userId(null)
                .username("null-claim-user")
                .role(null)
                .build();

        String token = jwtTokenProvider.generateAccessToken(payloadWithNulls);
        Claims claims = jwtTokenProvider.extractAllClaims(token);

        assertNotNull(token);
        assertNull(claims.get("userId"));
        assertNull(claims.get("role"));
        assertNull(claims.getSubject());
    }

    @Test
    void extractAllClaims_ExpiredToken_ThrowsExpiredJwtException() throws InterruptedException {
        JwtTokenProvider shortLivedProvider = new JwtTokenProvider(new ObjectMapper());
        ReflectionTestUtils.setField(shortLivedProvider, "jwtSecret", VALID_BASE64_SECRET);
        ReflectionTestUtils.setField(shortLivedProvider, "jwtExpiration", 1L);
        shortLivedProvider.init();

        JwtPayload payload = generateRandomPayload("ROLE_AUTHORIZED_USER");
        String expiredToken = shortLivedProvider.generateAccessToken(payload);

        Thread.sleep(10);

        assertThrows(ExpiredJwtException.class, () -> shortLivedProvider.extractAllClaims(expiredToken));
    }

    @Test
    void extractAllClaims_InvalidSignature_ThrowsSignatureException() {
        JwtTokenProvider attackerProvider = new JwtTokenProvider(new ObjectMapper());
        String attackerSecret = Base64.getEncoder().encodeToString("AttackerDifferentSecretKeyForHmacSha256Algorithm9876543210!@#".getBytes());
        ReflectionTestUtils.setField(attackerProvider, "jwtSecret", attackerSecret);
        ReflectionTestUtils.setField(attackerProvider, "jwtExpiration", VALID_EXPIRATION);
        attackerProvider.init();

        JwtPayload payload = generateRandomPayload("ROLE_ADMIN");
        String attackerToken = attackerProvider.generateAccessToken(payload);

        assertThrows(SignatureException.class, () -> jwtTokenProvider.extractAllClaims(attackerToken));
    }

    @Test
    void extractAllClaims_MalformedToken_ThrowsException() {
        String malformedToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.InvalidPayloadData";

        assertThrows(MalformedJwtException.class, () -> jwtTokenProvider.extractAllClaims(malformedToken));
        assertThrows(IllegalArgumentException.class, () -> jwtTokenProvider.extractAllClaims(""));
        assertThrows(IllegalArgumentException.class, () -> jwtTokenProvider.extractAllClaims(null));
    }
}