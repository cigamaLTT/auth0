package com.cigama.auth0.security;

import com.cigama.auth0.dto.userdetails.CustomUserDetails;
import com.cigama.auth0.entity.Role;
import com.cigama.auth0.entity.User;
import com.cigama.auth0.security.annotation.JwtClaim;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Field;
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
        jwtTokenProvider = new JwtTokenProvider();
        ReflectionTestUtils.setField(jwtTokenProvider, "jwtSecret", VALID_BASE64_SECRET);
        ReflectionTestUtils.setField(jwtTokenProvider, "jwtExpiration", VALID_EXPIRATION);
        jwtTokenProvider.init();
    }

    // --- Helpers ---

    private CustomUserDetails generateRandomUserDetails(Role role) {
        User mockUser = new User();
        mockUser.setUserId(UUID.randomUUID());
        mockUser.setEmail(UUID.randomUUID().toString().substring(0, 8) + "@test.local");
        mockUser.setUsername("user_" + UUID.randomUUID().toString().substring(0, 8));
        mockUser.setPassword("MockPassword123!");
        mockUser.setRole(role);
        mockUser.setIsAuthorized(true);
        return CustomUserDetails.build(mockUser);
    }

    // --- Test Cases ---

    @ParameterizedTest
    @EnumSource(Role.class)
    void generateAccessToken_SuccessForAllRoles(Role role) {
        CustomUserDetails userDetails = generateRandomUserDetails(role);

        String token = jwtTokenProvider.generateAccessToken(userDetails);

        assertNotNull(token);
        assertFalse(token.isBlank());
        assertEquals(3, token.split("\\.").length);
    }

    @Test
    void extractAllClaims_DynamicFieldsMatching() throws IllegalAccessException {
        CustomUserDetails userDetails = generateRandomUserDetails(Role.AUTHORIZED_USER);
        String token = jwtTokenProvider.generateAccessToken(userDetails);

        Claims claims = jwtTokenProvider.extractAllClaims(token);

        for (Field field : CustomUserDetails.class.getDeclaredFields()) {
            if (field.isAnnotationPresent(JwtClaim.class)) {
                field.setAccessible(true);
                Object expectedValue = field.get(userDetails);

                assertTrue(claims.containsKey(field.getName()));
                assertEquals(expectedValue.toString(), claims.get(field.getName(), String.class));
            }
        }
    }

    @Test
    void generateAccessToken_WithNullClaimValues_ShouldNotCrash() {
        CustomUserDetails userDetailsWithNulls = CustomUserDetails.builder()
                .userId(null)
                .username("null-claim-user@test.local")
                .password("Password123")
                .role(null)
                .build();

        String token = jwtTokenProvider.generateAccessToken(userDetailsWithNulls);
        Claims claims = jwtTokenProvider.extractAllClaims(token);

        assertNotNull(token);
        assertNull(claims.get("userId"));
        assertNull(claims.get("role"));
        assertEquals("null-claim-user@test.local", claims.getSubject());
    }

    @Test
    void extractAllClaims_ExpiredToken_ThrowsExpiredJwtException() throws InterruptedException {
        JwtTokenProvider shortLivedProvider = new JwtTokenProvider();
        ReflectionTestUtils.setField(shortLivedProvider, "jwtSecret", VALID_BASE64_SECRET);
        ReflectionTestUtils.setField(shortLivedProvider, "jwtExpiration", 1L);
        shortLivedProvider.init();

        CustomUserDetails userDetails = generateRandomUserDetails(Role.AUTHORIZED_USER);
        String expiredToken = shortLivedProvider.generateAccessToken(userDetails);

        Thread.sleep(10);

        assertThrows(ExpiredJwtException.class, () -> shortLivedProvider.extractAllClaims(expiredToken));
    }

    @Test
    void extractAllClaims_InvalidSignature_ThrowsSignatureException() {
        JwtTokenProvider attackerProvider = new JwtTokenProvider();
        String attackerSecret = Base64.getEncoder().encodeToString("AttackerDifferentSecretKeyForHmacSha256Algorithm9876543210!@#".getBytes());
        ReflectionTestUtils.setField(attackerProvider, "jwtSecret", attackerSecret);
        ReflectionTestUtils.setField(attackerProvider, "jwtExpiration", VALID_EXPIRATION);
        attackerProvider.init();

        CustomUserDetails userDetails = generateRandomUserDetails(Role.ADMIN);
        String attackerToken = attackerProvider.generateAccessToken(userDetails);

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