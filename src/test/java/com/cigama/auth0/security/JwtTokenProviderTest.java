package com.cigama.auth0.security;

import com.cigama.auth0.dto.JwtPayload;
import tools.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenProviderTest {

    // --- Variables ---

    private JwtTokenProvider jwtTokenProvider;
    private ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        jwtTokenProvider = new JwtTokenProvider(objectMapper);

        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair rsaPair = rsaGen.generateKeyPair();
        String rsaPriv = Base64.getEncoder().encodeToString(rsaPair.getPrivate().getEncoded());
        String rsaPub = Base64.getEncoder().encodeToString(rsaPair.getPublic().getEncoded());

        KeyPairGenerator mlDsaGen = KeyPairGenerator.getInstance("ML-DSA", "BC");
        KeyPair mlDsaPair = mlDsaGen.generateKeyPair();
        String mlPriv = Base64.getEncoder().encodeToString(mlDsaPair.getPrivate().getEncoded());
        String mlPub = Base64.getEncoder().encodeToString(mlDsaPair.getPublic().getEncoded());

        ReflectionTestUtils.setField(jwtTokenProvider, "rsaPrivateKeyStr", rsaPriv);
        ReflectionTestUtils.setField(jwtTokenProvider, "rsaPublicKeyStr", rsaPub);
        ReflectionTestUtils.setField(jwtTokenProvider, "mlDsaPrivateKeyStr", mlPriv);
        ReflectionTestUtils.setField(jwtTokenProvider, "mlDsaPublicKeyStr", mlPub);
        ReflectionTestUtils.setField(jwtTokenProvider, "jwtExpiration", 3600000L);

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
                .clientId("test-client")
                .build();
    }

    // --- Test Cases ---

    @Test
    void generateAndVerifyHybridToken_ShouldSucceed() {
        JwtPayload payload = generateRandomPayload("ROLE_ADMIN");

        String token = jwtTokenProvider.generateAccessToken(payload);
        assertNotNull(token);
        assertTrue(token.split("\\.").length == 3);

        Claims claims = jwtTokenProvider.extractAllClaims(token);
        assertEquals(payload.getUserId(), claims.getSubject());
        assertEquals(payload.getUsername(), claims.get("username"));
        assertEquals(payload.getRole(), claims.get("role"));
        assertEquals("test-client", claims.getAudience().iterator().next());
    }

    @Test
    void extractAllClaims_InvalidOuterSignature_ThrowsRuntimeException() {
         JwtPayload payload = generateRandomPayload("ROLE_USER");
         String token = jwtTokenProvider.generateAccessToken(payload);
         String tamperedToken = token.substring(0, token.length() - 5) + "abcde";

         assertThrows(RuntimeException.class, () -> jwtTokenProvider.extractAllClaims(tamperedToken));
    }

    @Test
    void generateAccessToken_WithNullClaimValues_ShouldNotCrash() {
        JwtPayload payloadWithNulls = JwtPayload.builder()
                .userId(null)
                .username(null)
                .role(null)
                .build();

        String token = jwtTokenProvider.generateAccessToken(payloadWithNulls);
        assertNotNull(token);

        Claims claims = jwtTokenProvider.extractAllClaims(token);
        assertNull(claims.getSubject());
        assertNull(claims.get("username"));
        assertNull(claims.get("role"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"invalid.token", "header.payload.signature.extra", "not-a-jwt"})
    void extractAllClaims_MalformedToken_ThrowsException(String malformedToken) {
        assertThrows(RuntimeException.class, () -> jwtTokenProvider.extractAllClaims(malformedToken));
    }

    @Test
    void extractAllClaims_ExpiredToken_ThrowsExpiredJwtException() throws Exception {
        JwtTokenProvider expiredProvider = new JwtTokenProvider(objectMapper);
        ReflectionTestUtils.setField(expiredProvider, "rsaPrivateKeyStr", ReflectionTestUtils.getField(jwtTokenProvider, "rsaPrivateKeyStr"));
        ReflectionTestUtils.setField(expiredProvider, "rsaPublicKeyStr", ReflectionTestUtils.getField(jwtTokenProvider, "rsaPublicKeyStr"));
        ReflectionTestUtils.setField(expiredProvider, "mlDsaPrivateKeyStr", ReflectionTestUtils.getField(jwtTokenProvider, "mlDsaPrivateKeyStr"));
        ReflectionTestUtils.setField(expiredProvider, "mlDsaPublicKeyStr", ReflectionTestUtils.getField(jwtTokenProvider, "mlDsaPublicKeyStr"));
        ReflectionTestUtils.setField(expiredProvider, "jwtExpiration", -5000L); // 5s in the past
        expiredProvider.init();

        JwtPayload payload = generateRandomPayload("ROLE_USER");
        String token = expiredProvider.generateAccessToken(payload);

        RuntimeException ex = assertThrows(RuntimeException.class, () -> jwtTokenProvider.extractAllClaims(token));
        assertTrue(ex.getCause() instanceof ExpiredJwtException);
    }

    @Test
    void verifyToken_WithInvalidInnerJwsFormat_ShouldThrowRuntimeException() {
        PrivateKey rsaPriv = (PrivateKey) ReflectionTestUtils.getField(jwtTokenProvider, "rsaPrivateKey");
        String fakeToken = Jwts.builder()
                .content("this-is-not-a-jws-dots-structure")
                .signWith(rsaPriv, Jwts.SIG.RS256)
                .compact();

        assertThrows(RuntimeException.class, () -> jwtTokenProvider.extractAllClaims(fakeToken));
    }

    @Test
    void verifyToken_WithFakeInnerSignature_ShouldThrowRuntimeException() throws Exception {
        JwtTokenProvider attackerProvider = new JwtTokenProvider(objectMapper);
        KeyPairGenerator mlDsaGen = KeyPairGenerator.getInstance("ML-DSA", "BC");
        KeyPair attackerMlDsa = mlDsaGen.generateKeyPair();

        ReflectionTestUtils.setField(attackerProvider, "rsaPrivateKeyStr", ReflectionTestUtils.getField(jwtTokenProvider, "rsaPrivateKeyStr"));
        ReflectionTestUtils.setField(attackerProvider, "rsaPublicKeyStr", ReflectionTestUtils.getField(jwtTokenProvider, "rsaPublicKeyStr"));
        ReflectionTestUtils.setField(attackerProvider, "mlDsaPrivateKeyStr", Base64.getEncoder().encodeToString(attackerMlDsa.getPrivate().getEncoded()));
        ReflectionTestUtils.setField(attackerProvider, "mlDsaPublicKeyStr", Base64.getEncoder().encodeToString(attackerMlDsa.getPublic().getEncoded()));
        ReflectionTestUtils.setField(attackerProvider, "jwtExpiration", 3600000L);
        attackerProvider.init();

        JwtPayload payload = generateRandomPayload("ROLE_ADMIN");
        String fakeToken = attackerProvider.generateAccessToken(payload);

        RuntimeException ex = assertThrows(RuntimeException.class, () -> jwtTokenProvider.extractAllClaims(fakeToken));
        assertTrue(ex.getMessage().contains("Inner ML-DSA signature failed"));
    }

    @Test
    void verifyToken_WithPlainRsa_ShouldThrowRuntimeException() {
        PrivateKey rsaPriv = (PrivateKey) ReflectionTestUtils.getField(jwtTokenProvider, "rsaPrivateKey");
        String plainToken = Jwts.builder()
                .subject("plain-test")
                .signWith(rsaPriv, Jwts.SIG.RS256)
                .compact();

        assertThrows(RuntimeException.class, () -> jwtTokenProvider.extractAllClaims(plainToken));
    }
}