package com.qbitspark.glueauthbackend.Oauth2Server.Clients.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuth2Controller {

    // If you still need a custom login endpoint, handle it here
    @GetMapping("/oauth2/custom-login")
    public String customLogin() {
        // This should redirect to the default login page if needed
        return "redirect:/login";
    }

    @GetMapping("/access-denied")
    public ResponseEntity<String> accessDenied() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied");
    }
}