package com.cigama.auth0.security;

import com.cigama.auth0.dto.JwtPayload;
import com.cigama.auth0.mapper.UserMapper;
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
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // --- Variables ---

    private final JwtTokenProvider tokenProvider;
    private final ObjectMapper objectMapper;
    private final UserMapper userMapper;

    // --- Core Methods ---

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String jwt = getJwtFromRequest(request);

        if (StringUtils.hasText(jwt)) {
            try {
                Claims claims = tokenProvider.extractAllClaims(jwt);
                JwtPayload payload = objectMapper.convertValue(claims, JwtPayload.class);

                if (StringUtils.hasText(payload.getUserId()) && StringUtils.hasText(payload.getRole())) {
                    UserDetails userDetails = userMapper.toCustomUserDetails(payload);

                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());

                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (ExpiredJwtException ex) {
                request.setAttribute("jwtExceptionType", "EXPIRED");
                request.setAttribute("jwtExceptionMessage", "Token has expired");
            } catch (MalformedJwtException ex) {
                request.setAttribute("jwtExceptionType", "MALFORMED");
                request.setAttribute("jwtExceptionMessage", "Token format is invalid");
            } catch (SignatureException ex) {
                request.setAttribute("jwtExceptionType", "INVALID_SIGNATURE");
                request.setAttribute("jwtExceptionMessage", "Invalid signature");
            } catch (UnsupportedJwtException ex) {
                request.setAttribute("jwtExceptionType", "UNSUPPORTED");
                request.setAttribute("jwtExceptionMessage", "Unsupported token format");
            } catch (IllegalArgumentException ex) {
                request.setAttribute("jwtExceptionType", "ILLEGAL_ARGUMENT");
                request.setAttribute("jwtExceptionMessage", "Token argument is invalid");
            } catch (Exception ex) {
                request.setAttribute("jwtExceptionType", "UNKNOWN");
                request.setAttribute("jwtExceptionMessage", "An unknown error occurred while validating the token");
            }
        }

        filterChain.doFilter(request, response);
    }

    // --- Private Helpers ---

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}