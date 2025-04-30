package com.qbitspark.glueauthbackend.DeveloperService.Auth.Auth2Handler;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.utils.CookieUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    @Value("${app.frontend.baseUrl}")
    private String frontendBaseUrl;

    private final CookieUtils cookieUtils;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {
        // Clear auth cookies
        cookieUtils.clearTokenCookies(response);

        // Redirect to frontend login page
        response.sendRedirect(frontendBaseUrl + "/login?logout=success");
    }
}