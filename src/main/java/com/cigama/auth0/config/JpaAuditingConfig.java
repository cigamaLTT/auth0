package com.cigama.auth0.config;

import com.cigama.auth0.dto.userdetails.CustomUserDetails;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class JpaAuditingConfig {

    @Bean
    public AuditorAware<String> auditorProvider() {
        return () -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || !authentication.isAuthenticated()) {
                // If it's a background task or system action
                return Optional.of("system");
            }

            Object principal = authentication.getPrincipal();

            if (principal instanceof CustomUserDetails userDetails) {
                // If it's a logged in user
                if (userDetails.getUserId() != null) {
                    return Optional.of(userDetails.getUserId());
                }
                // If it's a client party (M2M)
                if (userDetails.getClientId() != null) {
                    return Optional.of("client_party_" + userDetails.getClientId());
                }
            }

            if (principal instanceof String principalString) {
                if ("anonymousUser".equals(principalString)) {
                    return Optional.of("anonymous");
                }
                return Optional.of(principalString);
            }

            return Optional.of("anonymous");
        };
    }
}
