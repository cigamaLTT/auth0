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
import tools.jackson.databind.ObjectMapper;

import java.util.List;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RegistrationStreamListenerTest {

    @Mock
    private EmailService emailService;
    @Mock
    private RedisTemplate<String, Object> streamRedisTemplate;
    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private RegistrationStreamListener listener;

    private PendingRegistrationEvent event;
    private ObjectRecord<String, String> message;
    private String eventJson = "{\"email\":\"test@example.com\"}";

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() throws Exception {
        event = new PendingRegistrationEvent(
                "test@example.com",
                "testuser",
                "auth:lock:email:test@example.com",
                "123456"
        );
        message = mock(ObjectRecord.class);
        when(message.getValue()).thenReturn(eventJson);
        when(objectMapper.readValue(eventJson, PendingRegistrationEvent.class)).thenReturn(event);
    }

    @Test
    void onMessage_WhenEmailSucceeds_ShouldNotDeleteLocks() {
        // Act
        listener.onMessage(message);

        // Assert
        verify(emailService).sendOtpEmail(event.email(), event.otpCode());
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
