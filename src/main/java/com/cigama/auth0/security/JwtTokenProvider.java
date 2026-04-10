package com.cigama.auth0.security;

import com.cigama.auth0.dto.JwtPayload;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    // --- Variables ---

    @Value("${jwt.rsa.private-key}")
    private String rsaPrivateKeyStr;

    @Value("${jwt.rsa.public-key}")
    private String rsaPublicKeyStr;

    @Value("${jwt.mldsa.private-key}")
    private String mlDsaPrivateKeyStr;

    @Value("${jwt.mldsa.public-key}")
    private String mlDsaPublicKeyStr;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    private final ObjectMapper objectMapper;

    private PrivateKey rsaPrivateKey;
    private PublicKey rsaPublicKey;
    private PrivateKey mlDsaPrivateKey;
    private PublicKey mlDsaPublicKey;

    @PostConstruct
    public void init() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        this.rsaPrivateKey = loadPrivateKey(rsaPrivateKeyStr, "RSA");
        this.rsaPublicKey = loadPublicKey(rsaPublicKeyStr, "RSA");

        this.mlDsaPrivateKey = loadPrivateKey(mlDsaPrivateKeyStr, "ML-DSA");
        this.mlDsaPublicKey = loadPublicKey(mlDsaPublicKeyStr, "ML-DSA");
    }

    // --- Core Methods ---

    /**
     * Generates a Nested JWT:
     * 1. Inner JWS signed with ML-DSA (PQC) containing the payload.
     * 2. Outer JWS signed with RS256 wrapping the inner token.
     */
    public String generateAccessToken(JwtPayload payload) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);


        String innerToken = generateInnerToken(payload, expiryDate);


        return Jwts.builder()
                .header().contentType("application/jwt").and()
                .content(innerToken)
                .signWith(rsaPrivateKey, Jwts.SIG.RS256)
                .compact();
    }

    /**
     * Extracts and verifies claims from the Nested JWT:
     * 1. Verifies Outer JWS with RSA.
     * 2. Verifies Inner JWS with ML-DSA.
     */
    public Claims extractAllClaims(String token) {
        try {
            byte[] innerTokenBytes = Jwts.parser()
                    .verifyWith(rsaPublicKey)
                    .build()
                    .parseSignedContent(token)
                    .getPayload();
            
            String innerToken = new String(innerTokenBytes, StandardCharsets.UTF_8);

            return verifyInnerToken(innerToken);
        } catch (Exception e) {
            throw new RuntimeException("JWT verification failed: " + e.getMessage(), e);
        }
    }

    // --- Private Helpers ---

    private String generateInnerToken(JwtPayload payload, Date expiryDate) {
        try {
            String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    "{\"alg\":\"ML-DSA\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8)
            );

            Map<String, Object> claimsMap = objectMapper.convertValue(payload, new TypeReference<>() {});
            claimsMap.put("sub", payload.getUserId());
            claimsMap.put("iat", System.currentTimeMillis() / 1000);
            claimsMap.put("exp", expiryDate.getTime() / 1000);
            
            if (payload.getClientId() != null) {
                claimsMap.put("aud", Collections.singletonList(payload.getClientId()));
            }

            String payloadJson = objectMapper.writeValueAsString(claimsMap);
            String payloadBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    payloadJson.getBytes(StandardCharsets.UTF_8)
            );

            String signingInput = header + "." + payloadBase64;

            Signature signer = Signature.getInstance("ML-DSA", "BC");
            signer.initSign(mlDsaPrivateKey);
            signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = signer.sign();

            String signatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);

            return signingInput + "." + signatureBase64;
        } catch (Exception e) {
            throw new RuntimeException("Error generating inner PQC token", e);
        }
    }

    private Claims verifyInnerToken(String innerToken) {
        try {
            String[] parts = innerToken.split("\\.");
            if (parts.length != 3) {
                throw new RuntimeException("Invalid inner token format");
            }

            String signingInput = parts[0] + "." + parts[1];
            byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);

            Signature verifier = Signature.getInstance("ML-DSA", "BC");
            verifier.initVerify(mlDsaPublicKey);
            verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));

            if (!verifier.verify(signatureBytes)) {
                throw new RuntimeException("Inner ML-DSA signature failed");
            }

            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            Map<String, Object> claimsMap = objectMapper.readValue(payloadJson, new TypeReference<>() {});

            Number exp = (Number) claimsMap.get("exp");
            if (exp != null) {
                long expirationTimeMillis = exp.longValue() * 1000;
                if (expirationTimeMillis < System.currentTimeMillis()) {
                    throw new ExpiredJwtException(null, Jwts.claims(claimsMap), "Inner PQC token has expired");
                }
            }

            return Jwts.claims(claimsMap);
        } catch (ExpiredJwtException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Inner token verification error: " + e.getMessage(), e);
        }
    }

    private PrivateKey loadPrivateKey(String keyBase64, String algorithm) throws Exception {
        byte[] keyBytes = Decoders.BASE64.decode(keyBase64.replaceAll("\\s+", ""));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm, "BC");
        return kf.generatePrivate(spec);
    }

    private PublicKey loadPublicKey(String keyBase64, String algorithm) throws Exception {
        byte[] keyBytes = Decoders.BASE64.decode(keyBase64.replaceAll("\\s+", ""));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm, "BC");
        return kf.generatePublic(spec);
    }
}
