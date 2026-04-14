package com.cigama.auth0.mapper;

import com.cigama.auth0.dto.cache.PendingUserData;
import com.cigama.auth0.dto.request.RegisterRequest;
import com.cigama.auth0.entity.User;
import com.cigama.auth0.event.dto.PendingRegistrationEvent;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest
class RegistrationMapperTest {

    // --- Fields ---

    @Autowired
    private RegistrationMapper registrationMapper;

    // --- Test Cases ---

    @Test
    void toPendingUserData_ShouldMapCorrectly() {
        // Arrange
        RegisterRequest request = new RegisterRequest(
                "test@example.com",
                "0123456789",
                "Password123",
                "Password123",
                "John",
                "Doe",
                "johndoe",
                LocalDate.of(1990, 1, 1)
        );
        
        String encodedPass = "encodedPass";
        String otp = "123456";
        String clientId = "client-uuid";

        // Act
        PendingUserData pending = registrationMapper.toPendingUserData(request, encodedPass, otp, clientId);

        // Assert
        assertNotNull(pending);
        assertEquals(request.email(), pending.email());
        assertEquals(encodedPass, pending.password());
        assertEquals(otp, pending.otpCode());
        assertEquals(clientId, pending.clientId());
    }

    @Test
    void toRegistrationEvent_ShouldMapCorrectly() {
        // Arrange
        RegisterRequest request = new RegisterRequest(
                "test@example.com", "0123456789", "pass", "pass", "John", "Doe", "johndoe", null
        );
        
        String registrationId = "lock:email:test@example.com";
        String otp = "123456";

        // Act
        PendingRegistrationEvent event = registrationMapper.toRegistrationEvent(request, registrationId, otp);

        // Assert
        assertNotNull(event);
        assertEquals(event.email(), request.email());
        assertEquals(event.username(), request.username());
        assertEquals(event.otpCode(), otp);
        assertEquals(event.registrationId(), registrationId);
    }

    @Test
    void pendingToUser_ShouldMapCorrectly() {
        // Arrange
        PendingUserData pending = new PendingUserData(
                "test@example.com",
                "0123456789",
                "encoded",
                "John",
                "Doe",
                "johndoe",
                null,
                "123456",
                null
        );

        // Act
        User user = registrationMapper.pendingToUser(pending);

        // Assert
        assertNotNull(user);
        assertEquals(pending.email(), user.getEmail());
        assertEquals(pending.password(), user.getPassword());
        assertEquals(pending.username(), user.getUsername());
    }
}
