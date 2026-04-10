package com.cigama.auth0.security;

import com.cigama.auth0.dto.JwtPayload;
import io.jsonwebtoken.JwtBuilder;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Decoders;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    // --- Variables ---

    @Value("${jwt.private-key}")
    private String privateKeyString;

    @Value("${jwt.public-key}")
    private String publicKeyString;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    private final ObjectMapper objectMapper;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    public void init() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        byte[] privateKeyBytes = Decoders.BASE64.decode(privateKeyString);
        this.privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        byte[] publicKeyBytes = Decoders.BASE64.decode(publicKeyString);
        this.publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
    }

    // --- Core Methods ---

    /**
     * Serializes the JwtPayload to a claims map via ObjectMapper, then builds and
     * signs the JWT.
     * The userId is also set as the JWT subject for standard compliance.
     */
    public String generateAccessToken(JwtPayload payload) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);

        Map<String, Object> claimsMap = objectMapper.convertValue(payload, new TypeReference<>() {});
        claimsMap.remove("clientId");

        JwtBuilder builder = Jwts.builder()
                .claims(claimsMap)
                .subject(payload.getUserId())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(privateKey);

        if (payload.getClientId() != null) {
            builder.audience().add(payload.getClientId()).and();
        }

        return builder.compact();
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}