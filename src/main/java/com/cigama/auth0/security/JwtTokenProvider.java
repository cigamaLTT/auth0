package com.cigama.auth0.security;

import com.cigama.auth0.dto.JwtPayload;
import io.jsonwebtoken.JwtBuilder;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    // --- Variables ---

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    private final ObjectMapper objectMapper;

    private SecretKey signingKey;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
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
                .signWith(signingKey);

        if (payload.getClientId() != null) {
            builder.audience().add(payload.getClientId()).and();
        }

        return builder.compact();
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}