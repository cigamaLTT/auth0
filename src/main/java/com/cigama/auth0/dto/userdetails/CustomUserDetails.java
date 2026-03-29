package com.cigama.auth0.dto.userdetails;

import com.cigama.auth0.entity.User;
import com.cigama.auth0.security.annotation.JwtClaim;
import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.lang.reflect.Field;
import java.util.*;

@Getter
@Builder
@AllArgsConstructor
public class CustomUserDetails implements UserDetails {

    // --- Variables ---

    @JwtClaim
    private UUID userId;

    @JwtClaim
    private String username;

    private String password;

    private boolean isEnabled;

    private Collection<? extends GrantedAuthority> authorities;

    @JwtClaim
    private String role;

    private static final List<Field> JWT_CLAIM_FIELDS = new ArrayList<>();
    private static final Map<Field, Field> ENTITY_TO_DTO_FIELDS = new HashMap<>();

    // --- Initialization ---

    static {
        for (Field dtoField : CustomUserDetails.class.getDeclaredFields()) {
            dtoField.setAccessible(true);

            if (dtoField.isAnnotationPresent(JwtClaim.class)) {
                JWT_CLAIM_FIELDS.add(dtoField);
            }

            try {
                Field entityField = User.class.getDeclaredField(dtoField.getName());
                if (dtoField.getType().isAssignableFrom(entityField.getType())) {
                    entityField.setAccessible(true);
                    ENTITY_TO_DTO_FIELDS.put(entityField, dtoField);
                }
            } catch (NoSuchFieldException e) {
                // Ignore fields that don't match entity
            }
        }
    }

    // --- Public Methods ---

    /**
     * Builds details from Entity using pre-cached reflection mappings.
     */
    public static CustomUserDetails build(User user) {
        CustomUserDetails details = CustomUserDetails.builder()
                .password(user.getPassword())
                .isEnabled(user.getIsAuthorized() != null ? user.getIsAuthorized() : true)
                .authorities(Collections.singletonList(new SimpleGrantedAuthority(user.getRole().getAuthority())))
                .build();

        for (Map.Entry<Field, Field> entry : ENTITY_TO_DTO_FIELDS.entrySet()) {
            try {
                Object value = entry.getKey().get(user);
                if (value != null) {
                    entry.getValue().set(details, value);
                }
            } catch (IllegalAccessException e) {
                throw new RuntimeException("Entity-to-DTO mapping failed", e);
            }
        }

        // Special handling for role string from Enum
        details.role = user.getRole().getAuthority();
        
        return details;
    }

    /**
     * Reconstructs details from JWT Claims for a stateless authentication flow.
     */
    public static CustomUserDetails build(Claims claims) {
        CustomUserDetails details = CustomUserDetails.builder()
                .password("")
                .isEnabled(true)
                .build();

        for (Field field : JWT_CLAIM_FIELDS) {
            try {
                Object value = claims.get(field.getName());
                if (value != null) {
                    if (field.getType().equals(UUID.class) && value instanceof String) {
                        field.set(details, UUID.fromString((String) value));
                    } else if (field.getType().equals(String.class)) {
                        field.set(details, value.toString());
                    } else {
                        field.set(details, value);
                    }
                }
            } catch (IllegalAccessException e) {
                throw new RuntimeException("Claims-to-DTO mapping failed", e);
            }
        }

        if (details.role != null) {
            details.authorities = Collections.singletonList(new SimpleGrantedAuthority(details.role));
        }

        return details;
    }

    /**
     * Reconstructs minimal details from username and role strings.
     * Used by JwtAuthenticationFilter for stateless auth.
     */
    public static CustomUserDetails build(String email, String role) {
        return CustomUserDetails.builder()
                .username(email)
                .password("")
                .isEnabled(true)
                .authorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())))
                .role(role)
                .build();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }
}
