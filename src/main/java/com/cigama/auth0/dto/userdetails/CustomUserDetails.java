package com.cigama.auth0.dto.userdetails;

import com.cigama.auth0.entity.User;
import com.cigama.auth0.security.annotation.JwtClaim;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.UUID;

@Getter
@Builder
@AllArgsConstructor
public class CustomUserDetails implements UserDetails {

    // --- Variables ---

    @JwtClaim("userId")
    private final UUID userId;

    @JwtClaim("email")
    private final String username;

    private final String password;

    private final boolean isEnabled;

    private final Collection<? extends GrantedAuthority> authorities;

    @JwtClaim("role")
    private final String role;

    // --- Public Methods ---

    public static CustomUserDetails build(User user) {
        return CustomUserDetails.builder()
                .userId(user.getUserId())
                .username(user.getEmail())
                .password(user.getPassword())
                .isEnabled(user.getIsAuthorized() != null ? user.getIsAuthorized() : true)
                .authorities(Collections.singletonList(new SimpleGrantedAuthority(user.getRole().getAuthority())))
                .role(user.getRole().getAuthority())
                .build();
    }

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
