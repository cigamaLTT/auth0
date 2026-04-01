package com.cigama.auth0.service.impl;

import com.cigama.auth0.entity.RefreshToken;
import com.cigama.auth0.repository.ClientAppRepository;
import com.cigama.auth0.repository.RefreshTokenRepository;
import com.cigama.auth0.repository.UserRepository;
import com.cigama.auth0.security.JwtTokenProvider;
import com.cigama.auth0.service.TokenBlacklistService;
import com.cigama.auth0.service.ValidationService;
import com.cigama.auth0.mapper.UserMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    // --- Variables ---

    @Mock
    private UserRepository userRepository;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private ValidationService validationService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtTokenProvider jwtTokenProvider;
    @Mock
    private UserMapper userMapper;
    @Mock
    private ClientAppRepository clientAppRepository;
    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @InjectMocks
    private AuthServiceImpl authService;

    private String accessToken;
    private String refreshTokenRaw;
    private RefreshToken refreshTokenEntity;

    @BeforeEach
    void setUp() {
        accessToken = "valid_access_token";
        refreshTokenRaw = "valid_refresh_token_raw";
        refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setUserId(UUID.randomUUID());
        refreshTokenEntity.setIsRevoked(false);
    }

    // --- Core Methods ---

    @Test
    void logout_WithValidTokens_ShouldRevokeAndBlacklist() {
        // Arrange
        Claims claims = mock(Claims.class);
        Date futureDate = new Date(System.currentTimeMillis() + 100000);
        
        when(validationService.validateRefreshToken(refreshTokenRaw)).thenReturn(refreshTokenEntity);
        when(jwtTokenProvider.extractAllClaims(accessToken)).thenReturn(claims);
        when(claims.getExpiration()).thenReturn(futureDate);

        // Act
        authService.logout(accessToken, refreshTokenRaw);

        // Assert
        assertTrue(refreshTokenEntity.getIsRevoked());
        verify(refreshTokenRepository, times(1)).save(refreshTokenEntity);
        verify(tokenBlacklistService, times(1)).blacklistToken(eq(accessToken), anyLong());
    }

    @Test
    void logout_WithExpiredAccessToken_ShouldRevokeRefreshAndSkipBlacklist() {
        // Arrange
        when(validationService.validateRefreshToken(refreshTokenRaw)).thenReturn(refreshTokenEntity);
        when(jwtTokenProvider.extractAllClaims(accessToken)).thenThrow(mock(ExpiredJwtException.class));

        // Act
        authService.logout(accessToken, refreshTokenRaw);

        // Assert
        assertTrue(refreshTokenEntity.getIsRevoked());
        verify(refreshTokenRepository, times(1)).save(refreshTokenEntity);
        verify(tokenBlacklistService, never()).blacklistToken(anyString(), anyLong());
    }

    @Test
    void logout_WithInvalidRefreshToken_ShouldThrowException() {
        // Arrange
        when(validationService.validateRefreshToken(refreshTokenRaw)).thenThrow(new RuntimeException("Invalid refresh token"));

        // Act & Assert
        assertThrows(RuntimeException.class, () -> authService.logout(accessToken, refreshTokenRaw));
        verify(refreshTokenRepository, never()).save(any());
        verify(tokenBlacklistService, never()).blacklistToken(anyString(), anyLong());
    }
}
