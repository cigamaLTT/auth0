package com.cigama.auth0.security;

import com.cigama.auth0.dto.JwtPayload;
import com.cigama.auth0.mapper.UserMapper;
import com.cigama.auth0.dto.userdetails.CustomUserDetails;
import tools.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    // --- Variables ---

    @Mock
    private JwtTokenProvider tokenProvider;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private UserMapper userMapper;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    // --- Setup ---

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        objectMapper = new ObjectMapper();
        jwtAuthenticationFilter = new JwtAuthenticationFilter(tokenProvider, objectMapper, userMapper);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // --- Tests ---

    @Test
    void doFilterInternal_ValidToken_SetsSecurityContext() throws ServletException, IOException {
        String token = "valid.jwt.token";
        String mockUserId = UUID.randomUUID().toString();
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);


        Claims claims = io.jsonwebtoken.Jwts.claims()
                .add("userId", mockUserId)
                .add("username", "user@test.local")
                .add("role", "ROLE_AUTHORIZED_USER")
                .build();
        
        when(tokenProvider.extractAllClaims(token)).thenReturn(claims);
        


        CustomUserDetails userDetails = CustomUserDetails.builder()
                .userId(mockUserId)
                .username("user@test.local")
                .role("ROLE_AUTHORIZED_USER")
                .enabled(true)
                .build();

        when(userMapper.toCustomUserDetails(any(JwtPayload.class))).thenReturn(userDetails);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(authentication);
        assertEquals("user@test.local", authentication.getName());
        assertTrue(authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_AUTHORIZED_USER")));

        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterInternal_NoToken_DoesNotSetSecurityContext() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn(null);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(tokenProvider, never()).extractAllClaims(anyString());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterInternal_InvalidHeaderFormat_DoesNotSetSecurityContext() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn("Basic invalidFormatToken");

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(tokenProvider, never()).extractAllClaims(anyString());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterInternal_MissingClaims_DoesNotSetSecurityContext() throws ServletException, IOException {
        String token = "token.missing.claims";
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);


        Claims claims = io.jsonwebtoken.Jwts.claims().build();
        when(tokenProvider.extractAllClaims(token)).thenReturn(claims);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @ParameterizedTest
    @MethodSource("provideJwtExceptions")
    void doFilterInternal_JwtExceptions_SetsRequestAttributes(Exception exception, String expectedType, String expectedMessage) throws ServletException, IOException {
        String token = "problematic.jwt.token";
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(tokenProvider.extractAllClaims(token)).thenThrow(exception);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(request, times(1)).setAttribute("jwtExceptionType", expectedType);
        verify(request, times(1)).setAttribute("jwtExceptionMessage", expectedMessage);
        verify(filterChain, times(1)).doFilter(request, response);
    }

    private static Stream<Arguments> provideJwtExceptions() {
        return Stream.of(
                Arguments.of(new ExpiredJwtException(null, null, "Expired"), "EXPIRED", "Token has expired"),
                Arguments.of(new MalformedJwtException("Malformed"), "MALFORMED", "Token format is invalid"),
                Arguments.of(new SignatureException("Signature"), "INVALID_SIGNATURE", "Invalid signature"),
                Arguments.of(new UnsupportedJwtException("Unsupported"), "UNSUPPORTED", "Unsupported token format"),
                Arguments.of(new IllegalArgumentException("Illegal"), "ILLEGAL_ARGUMENT", "Token argument is invalid"),
                Arguments.of(new RuntimeException("Unknown error"), "UNKNOWN", "An unknown error occurred while validating the token")
        );
    }
}
