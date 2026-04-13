package com.cigama.auth0.dto.userdetails;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class CustomUserDetails implements UserDetails {

    // --- Fields ---

    private String userId;
    private String username;
    private String password;
    private boolean enabled;
    private String role;
    private String clientId;

    public CustomUserDetails(String userId, String username, String password, boolean enabled, String role, String clientId) {
        this.userId = userId;
        this.username = username;
        this.password = password;
        this.enabled = enabled;
        this.role = role;
        this.clientId = clientId;
    }

    public String getUserId() {
        return userId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRole() {
        return role;
    }

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

    public static CustomUserDetailsBuilder builder() {
        return new CustomUserDetailsBuilder();
    }

    public static class CustomUserDetailsBuilder {
        private String userId;
        private String username;
        private String password;
        private boolean enabled;
        private String role;
        private String clientId;

        public CustomUserDetailsBuilder userId(String userId) {
            this.userId = userId;
            return this;
        }

        public CustomUserDetailsBuilder username(String username) {
            this.username = username;
            return this;
        }

        public CustomUserDetailsBuilder password(String password) {
            this.password = password;
            return this;
        }

        public CustomUserDetailsBuilder enabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        public CustomUserDetailsBuilder role(String role) {
            this.role = role;
            return this;
        }

        public CustomUserDetailsBuilder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public CustomUserDetails build() {
            return new CustomUserDetails(userId, username, password, enabled, role, clientId);
        }
    }
}
