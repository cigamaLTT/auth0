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

    // --- Core Methods ---

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        String jwtExceptionType = (String) request.getAttribute("jwtExceptionType");
        String jwtExceptionMessage = (String) request.getAttribute("jwtExceptionMessage");

        String errorMessage = "Unauthorized";
        if (jwtExceptionType != null && jwtExceptionMessage != null) {
            errorMessage = jwtExceptionMessage;
        } else if (authException != null && authException.getMessage() != null) {
            errorMessage = authException.getMessage();
        }

        String jsonResponse = """
                {
                    "status": %d,
                    "error": "Unauthorized",
                    "message": "%s",
                    "type": "%s",
                    "data": null
                }
                """.formatted(
                HttpStatus.UNAUTHORIZED.value(),
                errorMessage,
                jwtExceptionType != null ? jwtExceptionType : "AUTHENTICATION_FAILED"
        );

        response.getWriter().write(jsonResponse);
    }
}
