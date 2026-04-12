package com.cigama.auth0.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Blocks access to API documentation endpoints from non-localhost IPs.
 * This runs before the security chain so no authentication is needed from localhost.
 */
@Slf4j
@Component
public class LocalOnlyFilter extends OncePerRequestFilter {

    private static final String DOCS_PATH_PREFIX = "/api/docs";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String uri = request.getRequestURI();
        boolean isDocsPath = uri.startsWith("/api/docs") || 
                             uri.startsWith("/v3/api-docs") || 
                             uri.startsWith("/api/swagger-ui") ||
                             uri.startsWith("/swagger-ui");

        if (isDocsPath) {
            String remoteAddr = request.getRemoteAddr();
            log.info("Accessing documentation from IP: {}", remoteAddr);
            boolean isLocal = "127.0.0.1".equals(remoteAddr) || "::1".equals(remoteAddr) || "0:0:0:0:0:0:0:1".equals(remoteAddr);

            if (!isLocal) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
