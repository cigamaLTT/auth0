package com.cigama.auth0.service.impl;

import com.cigama.auth0.dto.request.*;
import com.cigama.auth0.dto.cache.PendingPasswordResetData;
import com.cigama.auth0.dto.cache.PendingUserData;
import com.cigama.auth0.dto.response.VerifyOtpResponse;
import com.cigama.auth0.entity.RefreshToken;
import com.cigama.auth0.entity.SecuritySettingType;
import com.cigama.auth0.entity.User;
import com.cigama.auth0.entity.Role;
import com.cigama.auth0.entity.UserSecuritySetting;
import com.cigama.auth0.event.dto.ForgotPasswordEvent;
import com.cigama.auth0.event.dto.PendingRegistrationEvent;
import com.cigama.auth0.mapper.PasswordResetMapper;
import com.cigama.auth0.mapper.RegistrationMapper;
import com.cigama.auth0.mapper.UserMapper;
import com.cigama.auth0.repository.ClientAppRepository;
import com.cigama.auth0.repository.RefreshTokenRepository;
import com.cigama.auth0.repository.UserRepository;
import com.cigama.auth0.security.JwtTokenProvider;
import com.cigama.auth0.service.EmailService;
import com.cigama.auth0.service.TokenBlacklistService;
import com.cigama.auth0.service.ValidationService;
import com.cigama.auth0.service.SecuritySettingService;
import com.cigama.auth0.service.OtpService;
import com.cigama.auth0.service.TokenService;
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
import org.springframework.data.redis.connection.stream.RecordId;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StreamOperations;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import tools.jackson.databind.ObjectMapper;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthServiceImplTest {

    // --- Fields ---

    @Mock
    private UserRepository userRepository;
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
    private PasswordResetMapper passwordResetMapper;
    @Mock
    private ClientAppRepository clientAppRepository;
    @Mock
    private TokenBlacklistService tokenBlacklistService;
    @Mock
    private SecuritySettingService securitySettingService;
    @Mock
    private OtpService otpService;
    @Mock
    private TokenService tokenService;
    @Mock
    private RedisTemplate<String, Object> streamRedisTemplate;
    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private AuthServiceImpl authService;

    private String accessToken;
    private String refreshTokenRaw;
    private RefreshToken refreshTokenEntity;
    private UUID userId;
    private UUID deviceId;

    // --- Setup ---

    @BeforeEach
    void setUp() {
        accessToken = "valid_access_token";
        refreshTokenRaw = "valid_refresh_token_raw";
        userId = UUID.randomUUID();
        deviceId = UUID.randomUUID();

        refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setUserId(userId);
        refreshTokenEntity.setDeviceId(deviceId);
        refreshTokenEntity.setIsRevoked(false);

        // Mock Redis Template operations
        when(streamRedisTemplate.opsForStream()).thenReturn(mock(StreamOperations.class));
        when(streamRedisTemplate.opsForValue()).thenReturn(mock(ValueOperations.class));

        // Inject @Value fields manually
        ReflectionTestUtils.setField(authService, "registrationStreamKey", "auth:registration:stream");
        ReflectionTestUtils.setField(authService, "passwordResetStreamKey", "auth:password-reset:stream");
        ReflectionTestUtils.setField(authService, "passwordResetExpiration", 600000L);

        ReflectionTestUtils.setField(authService, "loginTrackerStreamKey", "auth:login-tracker:stream");
        ReflectionTestUtils.setField(authService, "securityStreamKey", "auth:security:stream");
    }

    // --- Registration Tests ---

    @Test
    void register_WhenLocksSucceed_ShouldPushToStream() throws Exception {
        // Arrange
        RegisterRequest request = new RegisterRequest(
                "new@example.com", "0123456789", "Secure123", "Secure123", "First", "Last", "newuser", null
        );
        
        when(validationService.validateRegistration(any(), any())).thenReturn(null);
        when(passwordEncoder.encode(any())).thenReturn("hashed");
        
        PendingUserData pendingData = new PendingUserData(
                "new@example.com", "0123456789", "hashed", "First", "Last", "newuser", null, "123456", null
        );
        when(registrationMapper.toPendingUserData(any(), any(), any(), any())).thenReturn(pendingData);
        when(otpService.generateAndSaveRegistrationOtp(any())).thenReturn("123456");
        
        PendingRegistrationEvent event = new PendingRegistrationEvent("new@example.com", "newuser", "lockKey", "123456");
        when(registrationMapper.toRegistrationEvent(any(), any(), any())).thenReturn(event);
        
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        
        var opsForStream = mock(StreamOperations.class);
        when(streamRedisTemplate.opsForStream()).thenReturn(opsForStream);
        doReturn(mock(RecordId.class)).when(opsForStream).add(any());

        // Act
        authService.register(request, "api-key");

        // Assert
        verify(otpService).generateAndSaveRegistrationOtp(any());
        verify(opsForStream).add(any(org.springframework.data.redis.connection.stream.Record.class));
    }

    @Test
    void register_WhenLocksFail_ShouldThrowConflict() throws Exception {
        // Arrange
        RegisterRequest request = new RegisterRequest(
                "taken@example.com", "0123456789", "Secure123", "Secure123", "First", "Last", "takenuser", null
        );
        
        when(validationService.validateRegistration(any(), any())).thenReturn(null);
        when(passwordEncoder.encode(any())).thenReturn("hashed");
        when(otpService.generateAndSaveRegistrationOtp(any())).thenThrow(new RuntimeException("Conflict"));

        // Act & Assert
        assertThrows(RuntimeException.class, () -> authService.register(request, "api-key"));
    }

    // --- OTP Verification Tests ---

    @Test
    @SuppressWarnings("unchecked")
    void verifyOtp_WithValidOtp_ShouldSaveUserAndCleanup() throws Exception {
        // Arrange
        String email = "test@example.com";
        String otp = "123456";
        
        PendingUserData pendingData = new PendingUserData(
                email, "0123456789", "hashed", "First", "Last", "testuser", null, otp, null
        );
        when(otpService.verifyRegistrationOtp(email, otp)).thenReturn(pendingData);
        
        User user = new User();
        user.setUsername("testuser");
        when(registrationMapper.pendingToUser(any())).thenReturn(user);

        // Act
        authService.verifyOtp(email, otp);

        // Assert
        verify(userRepository).save(user);
        verify(otpService).verifyRegistrationOtp(email, otp);
        assertTrue(user.getIsAuthorized());
        assertNotNull(user.getSecuritySetting());
    }

    // --- Password Change Tests ---

    @Test
    void changePassword_WithValidData_ShouldUpdatePassword() {
        // Arrange
        ChangePasswordRequest request = new ChangePasswordRequest("oldPass", "newPass", "newPass", false);
        User user = new User();
        user.setUserId(userId);
        user.setPassword("hashedOldPass");
        user.setEmail("test@example.com");
        user.setSecuritySetting(new UserSecuritySetting());

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("oldPass", "hashedOldPass")).thenReturn(true);
        when(passwordEncoder.encode("newPass")).thenReturn("hashedNewPass");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        var opsForStream = mock(org.springframework.data.redis.core.StreamOperations.class);
        when(streamRedisTemplate.opsForStream()).thenReturn(opsForStream);

        // Act
        authService.changePassword(userId, request);

        // Assert
        assertEquals("hashedNewPass", user.getPassword());
        verify(userRepository).save(user);
        verify(opsForStream, atLeastOnce()).add(any(org.springframework.data.redis.connection.stream.Record.class));
    }

    @Test
    void changePassword_WithLogoutAll_ShouldRevokeAllTokens() {
        // Arrange
        ChangePasswordRequest request = new ChangePasswordRequest("oldPass", "newPass", "newPass", true);
        User user = new User();
        user.setUserId(userId);
        user.setPassword("hashedOldPass");
        user.setEmail("test@example.com");
        user.setSecuritySetting(new UserSecuritySetting());

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("oldPass", "hashedOldPass")).thenReturn(true);
        when(passwordEncoder.encode("newPass")).thenReturn("hashedNewPass");

        // Act
        authService.changePassword(userId, request);

        // Assert
        verify(tokenService).revokeAllTokens(userId);
        verify(userRepository).save(user);
    }

    @Test
    void changePassword_WhenOtpRequired_ShouldThrowForbidden() {
        // Arrange
        ChangePasswordRequest request = new ChangePasswordRequest("oldPass", "newPass", "newPass", false);
        User user = new User();
        UserSecuritySetting setting = new UserSecuritySetting();
        setting.setRequireOtpForPassword(true);
        user.setSecuritySetting(setting);

        when(securitySettingService.isOtpRequired(userId, SecuritySettingType.PASSWORD)).thenReturn(true);

        // Act & Assert
        assertThrows(RuntimeException.class, () -> authService.changePassword(userId, request));
        verify(userRepository, never()).save(any());
    }

    @Test
    void changePassword_WithIncorrectOldPassword_ShouldThrowBadRequest() {
        // Arrange
        ChangePasswordRequest request = new ChangePasswordRequest("wrongPass", "newPass", "newPass", false);
        User user = new User();
        user.setPassword("hashedOldPass");
        when(securitySettingService.isOtpRequired(userId, SecuritySettingType.PASSWORD)).thenReturn(false);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrongPass", "hashedOldPass")).thenReturn(false);

        // Act & Assert
        assertThrows(RuntimeException.class, () -> authService.changePassword(userId, request));
    }

    // --- Password Reset Tests ---

    @Test
    void forgotPassword_WhenUserExists_ShouldPushToStream() throws Exception {
        // Arrange
        String email = "test@example.com";
        ForgotPasswordRequest request = new ForgotPasswordRequest(email);
        User user = new User();
        user.setEmail(email);

        when(validationService.validateUserExistsByEmail(email)).thenReturn(Optional.of(user));
        when(otpService.generateAndSavePasswordResetOtp(email)).thenReturn("123456");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        var opsForStream = mock(StreamOperations.class);
        when(streamRedisTemplate.opsForStream()).thenReturn(opsForStream);
        doReturn(mock(RecordId.class)).when(opsForStream).add(any());

        ForgotPasswordEvent event = new ForgotPasswordEvent(email, "lockKey", "123456");
        when(passwordResetMapper.toForgotPasswordEvent(any(), any(), any())).thenReturn(event);

        // Act
        authService.forgotPassword(request);

        // Assert
        verify(opsForStream).add(any(org.springframework.data.redis.connection.stream.Record.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void verifyOtpForPasswordReset_WithValidOtp_ShouldReturnResetToken() throws Exception {
        // Arrange
        String email = "test@example.com";
        String otp = "123456";

        when(jwtTokenProvider.generateActionToken(anyString(), anyString(), anyLong())).thenReturn("reset-token");

        // Act
        VerifyOtpResponse response = authService.verifyOtpForPasswordReset(email, otp);

        // Assert
        assertEquals("reset-token", response.resetToken());
        verify(otpService).verifyPasswordResetOtp(email, otp);
    }

    @Test
    void resetPassword_WithValidToken_ShouldUpdatePassword() {
        // Arrange
        String resetToken = "valid-reset-token";
        ResetPasswordRequest request = new ResetPasswordRequest("newPass", "newPass", false);
        Claims claims = mock(Claims.class);
        String email = "test@example.com";
        User user = new User();
        user.setEmail(email);

        when(tokenBlacklistService.isBlacklisted(resetToken)).thenReturn(false);
        when(jwtTokenProvider.extractAllClaims(resetToken)).thenReturn(claims);
        when(claims.get("purpose")).thenReturn("PASSWORD_RESET");
        when(claims.getSubject()).thenReturn(email);
        when(claims.getExpiration()).thenReturn(new Date(System.currentTimeMillis() + 100000));
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("newPass")).thenReturn("hashedNewPass");

        // Act
        authService.resetPassword(resetToken, request);

        // Assert
        assertEquals("hashedNewPass", user.getPassword());
        verify(userRepository).save(user);
        verify(tokenBlacklistService).blacklistToken(eq(resetToken), anyLong());
    }

    @Test
    void resetPassword_WithLogoutAll_ShouldRevokeAllTokens() {
        // Arrange
        String resetToken = "valid-reset-token";
        ResetPasswordRequest request = new ResetPasswordRequest("newPass", "newPass", true);
        Claims claims = mock(Claims.class);
        String email = "test@example.com";
        User user = new User();
        user.setUserId(userId);
        user.setEmail(email);

        when(tokenBlacklistService.isBlacklisted(resetToken)).thenReturn(false);
        when(jwtTokenProvider.extractAllClaims(resetToken)).thenReturn(claims);
        when(claims.get("purpose")).thenReturn("PASSWORD_RESET");
        when(claims.getSubject()).thenReturn(email);
        when(claims.getExpiration()).thenReturn(new Date(System.currentTimeMillis() + 100000));
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("newPass")).thenReturn("hashedNewPass");

        // Act
        authService.resetPassword(resetToken, request);

        // Assert
        verify(tokenService).revokeAllTokens(userId);
        verify(userRepository).save(user);
    }

    // --- Logout Tests ---

    @Test
    void logout_WithValidToken_ShouldRevokeAndBlacklist() {
        // Arrange
        Claims claims = mock(Claims.class);
        Date futureDate = new Date(System.currentTimeMillis() + 100000);
        
        when(jwtTokenProvider.extractAllClaims(accessToken)).thenReturn(claims);
        when(claims.getSubject()).thenReturn(userId.toString());
        when(claims.get("deviceId")).thenReturn(deviceId.toString());
        when(claims.getExpiration()).thenReturn(futureDate);

        // Act
        authService.logout(accessToken);

        // Assert
        verify(tokenService).revokeTokens(eq(userId), eq(deviceId));
        verify(tokenBlacklistService).blacklistToken(eq(accessToken), anyLong());
    }

    @Test
    void logout_WithExpiredAccessToken_ShouldReturnEarly() {
        // Arrange
        when(jwtTokenProvider.extractAllClaims(accessToken)).thenThrow(new ExpiredJwtException(null, null, "expired"));

        // Act
        authService.logout(accessToken);

        // Assert
        verifyNoInteractions(tokenService);
        verifyNoInteractions(tokenBlacklistService);
    }

    @Test
    void logout_MultiDevice_ShouldRevokeOnlyTargetDevice() {
        // Arrange
        UUID otherDeviceId = UUID.randomUUID();
        Claims claims = mock(Claims.class);
        Date futureDate = new Date(System.currentTimeMillis() + 100000);

        when(jwtTokenProvider.extractAllClaims(accessToken)).thenReturn(claims);
        when(claims.getSubject()).thenReturn(userId.toString());
        when(claims.get("deviceId")).thenReturn(deviceId.toString());
        when(claims.getExpiration()).thenReturn(futureDate);

        // Act
        authService.logout(accessToken);
 
        // Assert
        verify(tokenService).revokeTokens(userId, deviceId);
    }

    @Test
    void logout_WithMissingClaims_ShouldBlacklistButNotRevoke() {
        // Arrange
        Claims claims = mock(Claims.class);
        Date futureDate = new Date(System.currentTimeMillis() + 100000);

        when(jwtTokenProvider.extractAllClaims(accessToken)).thenReturn(claims);
        when(claims.getSubject()).thenReturn(null); // Missing userId
        when(claims.get("deviceId")).thenReturn(null); // Missing deviceId
        when(claims.getExpiration()).thenReturn(futureDate);

        // Act
        authService.logout(accessToken);

        // Assert
        verifyNoInteractions(tokenService);
        verify(tokenBlacklistService).blacklistToken(eq(accessToken), anyLong());
    }

    // --- Login & Lockout Tests ---

    @Test
    void login_WhenLocked_ShouldThrowLockedException() {
        LoginRequest request = new LoginRequest("user", "pass", null, null);
        String identifier = "user";
        String lockoutKey = "auth:lockout:" + identifier;
        
        when(streamRedisTemplate.hasKey(lockoutKey)).thenReturn(true);

        assertThrows(RuntimeException.class, () -> authService.login(request, null, null));
    }


    @Test
    void login_WhenFailed_ShouldPublishLoginEvent() throws Exception {
        LoginRequest request = new LoginRequest("user", "wrong-pass", null, null);
        String identifier = "user";
        
        when(streamRedisTemplate.hasKey(anyString())).thenReturn(false);
        when(validationService.validateLogin(request)).thenThrow(new com.cigama.auth0.exception.CustomException(org.springframework.http.HttpStatus.UNAUTHORIZED, "Invalid credentials"));
        
        var opsForStream = mock(StreamOperations.class);
        when(streamRedisTemplate.opsForStream()).thenReturn(opsForStream);
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        assertThrows(RuntimeException.class, () -> authService.login(request, null, null));
        
        verify(opsForStream).add(any(org.springframework.data.redis.connection.stream.Record.class));
    }
}
