package com.cigama.auth0.dto.userdetails;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter
@Builder
@AllArgsConstructor
public class CustomUserDetails implements UserDetails {

    // --- Fields ---

    private String userId;
    private String username;
    private String password;
    private boolean enabled;
    private String role;
    private String clientId;

    // --- UserDetails Interface ---

    /**
     * Computes granted authorities on demand from the role string.
     * Avoids storing a Collection field and eliminates mapping complexity.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (role != null) return List.of(new SimpleGrantedAuthority(role));
        return List.of();
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
        return enabled;
    }
}
