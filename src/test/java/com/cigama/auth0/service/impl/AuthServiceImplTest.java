package com.cigama.auth0.service.impl;

import com.cigama.auth0.entity.RefreshToken;
import com.cigama.auth0.repository.ClientAppRepository;
import com.cigama.auth0.repository.RefreshTokenRepository;
import com.cigama.auth0.repository.UserRepository;
import com.cigama.auth0.security.JwtTokenProvider;
import com.cigama.auth0.service.TokenBlacklistService;
import com.cigama.auth0.service.ValidationService;
import com.cigama.auth0.mapper.UserMapper;
import com.cigama.auth0.mapper.RegistrationMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;
import tools.jackson.databind.ObjectMapper;
import com.cigama.auth0.dto.request.RegisterRequest;
import com.cigama.auth0.dto.cache.PendingUserData;
import com.cigama.auth0.entity.User;
import com.cigama.auth0.entity.Role;
import com.cigama.auth0.event.dto.PendingRegistrationEvent;

import java.util.Date;
import java.util.UUID;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
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
    private RegistrationMapper registrationMapper;
    @Mock
    private ClientAppRepository clientAppRepository;
    @Mock
    private TokenBlacklistService tokenBlacklistService;
    @Mock
    private RedisTemplate<String, Object> streamRedisTemplate;
    @Mock
    private ObjectMapper objectMapper;

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

        // Inject @Value fields manually for unit test
        ReflectionTestUtils.setField(authService, "registrationStreamKey", "auth:registration:stream");
        ReflectionTestUtils.setField(authService, "emailLockPrefix", "auth:lock:email:");
        ReflectionTestUtils.setField(authService, "usernameLockPrefix", "auth:lock:username:");
        ReflectionTestUtils.setField(authService, "otpExpiration", 900);
    }

    // --- New Async Registration Tests ---

    @Test
    void register_WhenLocksSucceed_ShouldPushToStream() throws Exception {
        // Arrange
        RegisterRequest request = new RegisterRequest();
        request.setEmail("new@example.com");
        request.setUsername("newuser");
        request.setPassword("Secure123");
        
        when(validationService.validateRegistration(any(), any())).thenReturn(null);
        when(passwordEncoder.encode(any())).thenReturn("hashed");
        when(registrationMapper.toPendingUserData(any(), any(), any(), any())).thenReturn(new PendingUserData());
        when(registrationMapper.toRegistrationEvent(any(), any(), any())).thenReturn(new PendingRegistrationEvent());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        
        when(streamRedisTemplate.execute(any(RedisScript.class), anyList(), any(), any())).thenReturn(1L);
        
        // Use a realish-looking mock for opsForStream
        var opsForStream = mock(org.springframework.data.redis.core.StreamOperations.class);
        when(streamRedisTemplate.opsForStream()).thenReturn(opsForStream);
        doReturn(mock(org.springframework.data.redis.connection.stream.RecordId.class)).when(opsForStream).add(any());

        // Act
        authService.register(request, "api-key");

        // Assert
        verify(streamRedisTemplate).execute(any(RedisScript.class), anyList(), any(), any());
        verify(opsForStream).add(any(org.springframework.data.redis.connection.stream.Record.class));
    }

    @Test
    void register_WhenLocksFail_ShouldThrowException() throws Exception {
        // Arrange
        RegisterRequest request = new RegisterRequest();
        request.setEmail("taken@example.com");
        request.setUsername("takenuser");
        request.setPassword("Secure123");
        
        when(validationService.validateRegistration(any(), any())).thenReturn(null);
        when(passwordEncoder.encode(any())).thenReturn("hashed");
        when(registrationMapper.toPendingUserData(any(), any(), any(), any())).thenReturn(new PendingUserData());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        
        // Lua script returns 0 = conflict
        when(streamRedisTemplate.execute(any(RedisScript.class), anyList(), any(), any())).thenReturn(0L);

        // Act & Assert
        assertThrows(RuntimeException.class, () -> authService.register(request, "api-key"));
    }

    // --- OTP Verification Tests ---

    @Test
    void verifyOtp_WithValidOtp_ShouldSaveUserAndCleanup() throws Exception {
        // Arrange
        String email = "test@example.com";
        String otp = "123456";
        String json = "{\"otpCode\":\"123456\",\"username\":\"testuser\"}";
        
        ValueOperations<String, Object> valueOps = mock(ValueOperations.class);
        when(streamRedisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(json);
        
        PendingUserData pendingData = new PendingUserData();
        pendingData.setOtpCode(otp);
        pendingData.setUsername("testuser");
        when(objectMapper.readValue(anyString(), eq(PendingUserData.class))).thenReturn(pendingData);
        
        User user = new User();
        when(registrationMapper.pendingToUser(any())).thenReturn(user);

        // Act
        authService.verifyOtp(email, otp);

        // Assert
        verify(userRepository).save(user);
        verify(streamRedisTemplate).delete(anyList());
        assertTrue(user.getIsAuthorized());
    }

    @Test
    void verifyOtp_WithInvalidOtp_ShouldThrowException() throws Exception {
        // Arrange
        String email = "test@example.com";
        String otp = "wrong";
        String json = "{\"otpCode\":\"123456\"}";
        
        ValueOperations<String, Object> valueOps = mock(ValueOperations.class);
        when(streamRedisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(json);
        
        PendingUserData pendingData = new PendingUserData();
        pendingData.setOtpCode("123456");
        when(objectMapper.readValue(anyString(), eq(PendingUserData.class))).thenReturn(pendingData);

        // Act & Assert
        assertThrows(RuntimeException.class, () -> authService.verifyOtp(email, otp));
        verify(userRepository, never()).save(any());
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
