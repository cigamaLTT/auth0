package com.cigama.auth0.repository;

import com.cigama.auth0.entity.User;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class UserRepositoryTest {

    // --- Test Cases ---

    @Test
    void userEntity_CanBeInstantiated() {
        User user = new User();
        user.setEmail("test@example.com");
        user.setUsername("testuser");
        user.setPassword("password");

        assertNotNull(user.getEmail());
        assertNotNull(user.getUsername());
    }
}
