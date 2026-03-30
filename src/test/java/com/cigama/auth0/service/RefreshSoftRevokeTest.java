package com.cigama.auth0.service;

import com.cigama.auth0.entity.RefreshToken;
import com.cigama.auth0.exception.CustomException;
import com.cigama.auth0.repository.RefreshTokenRepository;
import com.cigama.auth0.service.impl.ValidationServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshSoftRevokeTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private ValidationServiceImpl validationService;

    private static final int GRACE_PERIOD = 15;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(validationService, "refreshGracePeriodSeconds", GRACE_PERIOD);
    }

    @Test
    void validateRefreshToken_RevokedWithinGracePeriod_ShouldPass() {
        UUID userId = UUID.randomUUID();
        RefreshToken token = new RefreshToken();
        token.setUserId(userId);
        token.setIsRevoked(true);
        token.setUpdatedAt(LocalDateTime.now().minusSeconds(5));
        token.setExpiredAt(LocalDateTime.now().plusDays(1));
        
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(token));

        assertDoesNotThrow(() -> validationService.validateRefreshToken("some-token"));
        verify(refreshTokenRepository, never()).deleteByUserId(any());
    }

    @Test
    void validateRefreshToken_RevokedAfterGracePeriod_ShouldThrowAndKillAll() {
        UUID userId = UUID.randomUUID();
        RefreshToken token = new RefreshToken();
        token.setUserId(userId);
        token.setIsRevoked(true);
        token.setUpdatedAt(LocalDateTime.now().minusSeconds(20));
        token.setExpiredAt(LocalDateTime.now().plusDays(1));
        
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(token));

        CustomException exception = assertThrows(CustomException.class, 
            () -> validationService.validateRefreshToken("some-token"));
        
        assertTrue(exception.getMessage().contains("token theft detected"));
        verify(refreshTokenRepository, times(1)).deleteByUserId(userId);
    }

    @Test
    void validateRefreshToken_NotRevoked_ShouldPass() {
        RefreshToken token = new RefreshToken();
        token.setIsRevoked(false);
        token.setExpiredAt(LocalDateTime.now().plusDays(1));
        
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(token));

        assertDoesNotThrow(() -> validationService.validateRefreshToken("some-token"));
    }
}
