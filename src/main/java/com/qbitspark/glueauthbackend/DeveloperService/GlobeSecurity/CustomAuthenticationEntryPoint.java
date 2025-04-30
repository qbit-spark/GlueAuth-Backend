package com.qbitspark.glueauthbackend.DeveloperService.GlobeSecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Value("${app.frontend.baseUrl}")
    private String frontendBaseUrl;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        // For API requests, return 401 Unauthorized
        if (request.getHeader("Accept") != null &&
                request.getHeader("Accept").contains("application/json")) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
        } else {
            // For browser requests, redirect to the frontend login page
            response.sendRedirect(frontendBaseUrl + "/login?error=unauthorized");
        }
    }
}