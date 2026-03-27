package com.cigama.auth0.security;

import com.cigama.auth0.dto.userdetails.CustomUserDetails;
import com.cigama.auth0.security.annotation.JwtClaim;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class JwtTokenProvider {

    // --- Variables ---

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    private SecretKey signingKey;
    private final List<ClaimFieldInfo> claimFields = new ArrayList<>();

    private static class ClaimFieldInfo {
        final String claimKey;
        final Field field;

        ClaimFieldInfo(String claimKey, Field field) {
            this.claimKey = claimKey;
            this.field = field;
        }
    }

    @PostConstruct
    public void init() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);

        for (Field field : CustomUserDetails.class.getDeclaredFields()) {
            if (field.isAnnotationPresent(JwtClaim.class)) {
                field.setAccessible(true);
                JwtClaim claimAnnotation = field.getAnnotation(JwtClaim.class);
                String claimKey = claimAnnotation.value().isEmpty() ? field.getName() : claimAnnotation.value();
                claimFields.add(new ClaimFieldInfo(claimKey, field));
            }
        }
    }

    // --- Core Methods ---

    public String generateAccessToken(CustomUserDetails userDetails) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);

        Map<String, Object> claimsMap = new HashMap<>();

        for (ClaimFieldInfo info : claimFields) {
            try {
                Object value = info.field.get(userDetails);
                if (value != null) {
                    claimsMap.put(info.claimKey, value.toString());
                }
            } catch (IllegalAccessException e) {
                throw new RuntimeException("Error accessing field for JWT claim", e);
            }
        }

        return Jwts.builder()
                .claims(claimsMap)
                .subject(userDetails.getUsername())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(signingKey)
                .compact();
    }

    // --- Private Helpers ---

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}