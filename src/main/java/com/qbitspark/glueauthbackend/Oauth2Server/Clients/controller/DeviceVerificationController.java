package com.qbitspark.glueauthbackend.Oauth2Server.Clients.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;

@Controller
public class DeviceVerificationController {

    private final OAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository clientRepository;

    @Autowired
    public DeviceVerificationController(JdbcTemplate jdbcTemplate, RegisteredClientRepository clientRepository) {
        // Create authorization service for this controller only - not as a bean
        this.authorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, clientRepository);
        this.clientRepository = clientRepository;
    }

    @GetMapping("/device-verification")
    public String showVerificationForm(@RequestParam(value = "user_code", required = false) String userCode,
                                       Model model, Principal principal) {
        // If user code is provided
        if (userCode != null) {
            model.addAttribute("userCode", userCode);

            // If user is already authenticated, try to look up the client info
            if (principal != null) {
                OAuth2Authorization authorization = authorizationService.findByToken(
                        userCode, new OAuth2TokenType("user_code"));

                if (authorization != null) {
                    try {
                        // Add client name to model if available
                        var client = clientRepository.findById(authorization.getRegisteredClientId());
                        if (client != null) {
                            model.addAttribute("clientName", client.getClientName());
                            model.addAttribute("scopes", String.join(", ", authorization.getAuthorizedScopes()));
                        }
                    } catch (Exception e) {
                        // Ignore errors retrieving client details
                    }
                }
            }
        }

        return "device-verification";
    }

    @PostMapping("/device-verification")
    public String processVerification(@RequestParam("user_code") String userCode,
                                      Principal principal,
                                      Model model) {
        // Find the authorization by user code
        OAuth2Authorization authorization = authorizationService.findByToken(
                userCode, new OAuth2TokenType("user_code"));

        if (authorization == null) {
            // Invalid or expired user code
            model.addAttribute("error", "Invalid verification code. Please try again.");
            return "device-verification";
        }

        // If user is not authenticated, redirect to login with correct client ID
        if (principal == null) {
            String clientId = authorization.getRegisteredClientId();
            System.out.println("🚨🚨Redirecting to custom login for client ID: " + clientId);
            return "redirect:/custom-login?client_id=" + clientId + "&device_code=" + userCode;
        }

        // Update the authorization with the authenticated user's principal name
        OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
                .principalName(principal.getName())
                .build();

        // Save the updated authorization
        authorizationService.save(updatedAuthorization);

        return "device-verification-success";
    }
}