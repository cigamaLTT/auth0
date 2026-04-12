package com.cigama.auth0.event.listener;

import com.cigama.auth0.event.dto.PendingRegistrationEvent;
import com.cigama.auth0.service.EmailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.connection.stream.ObjectRecord;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.List;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RegistrationStreamListenerTest {

    @Mock
    private EmailService emailService;
    @Mock
    private RedisTemplate<String, Object> streamRedisTemplate;

    @InjectMocks
    private RegistrationStreamListener listener;

    private PendingRegistrationEvent event;
    private ObjectRecord<String, PendingRegistrationEvent> message;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        event = PendingRegistrationEvent.builder()
                .email("test@example.com")
                .username("testuser")
                .registrationId("auth:lock:email:test@example.com")
                .otpCode("123456")
                .build();
        message = mock(ObjectRecord.class);
        when(message.getValue()).thenReturn(event);
    }

    @Test
    void onMessage_WhenEmailSucceeds_ShouldNotDeleteLocks() {
        // Act
        listener.onMessage(message);

        // Assert
        verify(emailService).sendOtpEmail(event.getEmail(), event.getOtpCode());
        verify(streamRedisTemplate, never()).delete(anyList());
    }

    @Test
    void onMessage_WhenEmailFails_ShouldInitiateRevert() {
        // Arrange
        doThrow(new RuntimeException("Email service down"))
                .when(emailService).sendOtpEmail(anyString(), anyString());

        // Act
        listener.onMessage(message);

        // Assert
        verify(streamRedisTemplate).delete(anyList());
    }
}
