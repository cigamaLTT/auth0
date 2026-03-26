package com.cigama.auth0.security;

import com.cigama.auth0.dto.userdetails.CustomUserDetails;
import com.cigama.auth0.security.annotation.JwtClaim;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.lang.reflect.Field;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenProvider {

    // --- Variables ---

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    // --- Core Methods ---

    public String generateAccessToken(CustomUserDetails userDetails) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);

        Map<String, Object> claimsMap = new HashMap<>();

        for (Field field : CustomUserDetails.class.getDeclaredFields()) {
            if (field.isAnnotationPresent(JwtClaim.class)) {
                field.setAccessible(true);
                try {
                    Object value = field.get(userDetails);
                    if (value != null) {
                        JwtClaim claimAnnotation = field.getAnnotation(JwtClaim.class);
                        String claimKey = claimAnnotation.value().isEmpty() ? field.getName() : claimAnnotation.value();
                        claimsMap.put(claimKey, value.toString());
                    }
                } catch (IllegalAccessException e) {
                    throw new RuntimeException("Error accessing field for JWT claim", e);
                }
            }
        }

        return Jwts.builder()
                .claims(claimsMap)
                .subject(userDetails.getUsername())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    // --- Private Helpers ---

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}