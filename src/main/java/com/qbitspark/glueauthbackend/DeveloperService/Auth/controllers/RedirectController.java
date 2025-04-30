package com.qbitspark.glueauthbackend.DeveloperService.Auth.controllers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
@RequestMapping("/redirect")
public class RedirectController {

    @Value("${app.frontend.baseUrl}")
    private String frontendBaseUrl;

    @GetMapping("/login")
    public void redirectToLogin(HttpServletResponse response) throws IOException {
        response.sendRedirect(frontendBaseUrl + "/login");
    }

    @GetMapping("/unauthorized")
    public void redirectToUnauthorized(HttpServletResponse response) throws IOException {
        response.sendRedirect(frontendBaseUrl + "/login?error=unauthorized");
    }

    @GetMapping("/dashboard")
    public void redirectToDashboard(HttpServletResponse response) throws IOException {
        response.sendRedirect(frontendBaseUrl + "/dashboard");
    }
}