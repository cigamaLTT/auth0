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

    @Autowired
    private RegistrationMapper registrationMapper;

    @Test
    void toPendingUserData_ShouldMapCorrectly() {
        // Arrange
        RegisterRequest request = new RegisterRequest();
        request.setEmail("test@example.com");
        request.setFirstName("John");
        request.setLastName("Doe");
        request.setUsername("johndoe");
        request.setDateOfBirth(LocalDate.of(1990, 1, 1));
        
        String encodedPass = "encodedPass";
        String otp = "123456";
        String clientId = "client-uuid";

        // Act
        PendingUserData pending = registrationMapper.toPendingUserData(request, encodedPass, otp, clientId);

        // Assert
        assertNotNull(pending);
        assertEquals(request.getEmail(), pending.getEmail());
        assertEquals(encodedPass, pending.getPassword());
        assertEquals(otp, pending.getOtpCode());
        assertEquals(clientId, pending.getClientId());
    }

    @Test
    void toRegistrationEvent_ShouldMapCorrectly() {
        // Arrange
        RegisterRequest request = new RegisterRequest();
        request.setEmail("test@example.com");
        request.setUsername("johndoe");
        
        String registrationId = "lock:email:test@example.com";
        String otp = "123456";

        // Act
        PendingRegistrationEvent event = registrationMapper.toRegistrationEvent(request, registrationId, otp);

        // Assert
        assertNotNull(event);
        assertEquals(request.getEmail(), event.getEmail());
        assertEquals(request.getUsername(), event.getUsername());
        assertEquals(registrationId, event.getRegistrationId());
        assertEquals(otp, event.getOtpCode());
    }

    @Test
    void pendingToUser_ShouldMapCorrectly() {
        // Arrange
        PendingUserData pending = PendingUserData.builder()
                .email("test@example.com")
                .password("encoded")
                .firstName("John")
                .lastName("Doe")
                .username("johndoe")
                .build();

        // Act
        User user = registrationMapper.pendingToUser(pending);

        // Assert
        assertNotNull(user);
        assertEquals(pending.getEmail(), user.getEmail());
        assertEquals(pending.getPassword(), user.getPassword());
        assertEquals(pending.getUsername(), user.getUsername());
    }
}
