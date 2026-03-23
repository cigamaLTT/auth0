package com.cigama.auth0.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        String jwtExceptionMessage = (String) request.getAttribute("jwtException");
        String errorMessage = (jwtExceptionMessage != null) ? jwtExceptionMessage : authException.getMessage();

        String jsonResponse = String.format(
                "{\"status\": %d, \"message\": \"Unauthorized: %s\", \"data\": null}",
                HttpStatus.UNAUTHORIZED.value(),
                errorMessage
        );

        response.getWriter().write(jsonResponse);
    }
}