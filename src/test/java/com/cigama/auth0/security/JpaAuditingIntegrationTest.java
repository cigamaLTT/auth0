package com.cigama.auth0.security;

import com.cigama.auth0.entity.User;
import com.cigama.auth0.repository.UserRepository;
import com.cigama.auth0.entity.Role;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Transactional
public class JpaAuditingIntegrationTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    @WithMockUser(username = "test-admin", roles = {"ADMIN"})
    void shouldPopulateAuditFields_WhenUserIsSaved() {
        // Arrange
        User user = new User();
        user.setEmail("audit-test@example.com");
        user.setUsername("audituser");
        user.setPassword("password123");
        user.setRole(Role.AUTHORIZED_USER);

        // Act
        User savedUser = userRepository.saveAndFlush(user);

        // Assert
        assertNotNull(savedUser.getCreatedAt(), "CreatedAt should be populated");
        assertNotNull(savedUser.getUpdatedAt(), "UpdatedAt should be populated");
        assertNotNull(savedUser.getCreatedBy(), "CreatedBy should be populated");
        assertEquals("anonymous", savedUser.getCreatedBy(), "CreatedBy should be anonymous for register if no ID in token (our current logic defaults to anonymous/system)");
        
        // Note: Our AuditorAware logic returns user ID if found in CustomUserDetails. 
        // WithMockUser doesn't put CustomUserDetails by default, it puts a standard User.
        // So it should hit the 'principal instanceof String' logic if it's 'test-admin'
    }

    @Test
    void shouldPopulateSystemAuditor_WhenNoSecurityContext() {
        // Arrange
        User user = new User();
        user.setEmail("system-test@example.com");
        user.setUsername("systemuser");
        user.setPassword("password123");
        user.setRole(Role.AUTHORIZED_USER);

        // Act
        // SecurityContext is null here
        User savedUser = userRepository.saveAndFlush(user);

        // Assert
        assertEquals("system", savedUser.getCreatedBy());
    }
}
