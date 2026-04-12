package com.cigama.auth0.mapper;

import com.cigama.auth0.dto.JwtPayload;
import com.cigama.auth0.entity.Role;
import com.cigama.auth0.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest
class UserMapperTest {

    @Autowired
    private UserMapper userMapper;

    @Test
    void toJwtPayload_ShouldMapCorrectly() {
        // Arrange
        User user = new User();
        user.setUsername("testuser");
        user.setRole(Role.ADMIN);
        String clientId = "client-123";

        // Act
        JwtPayload payload = userMapper.toJwtPayload(user, clientId);

        // Assert
        assertNotNull(payload);
        assertEquals(user.getUsername(), payload.getUsername());
        assertEquals(user.getRole().getAuthority(), payload.getRole());
        assertEquals(clientId, payload.getClientId());
    }
}
