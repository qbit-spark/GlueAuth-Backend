package com.qbitspark.glueauthbackend.DeveloperService.Auth.controllers;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads.CreateAccountRequestBody;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads.LoginRequestBody;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads.ResetPasswordRequestBody;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.services.AccountService;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.VerificationException;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeResponseBody.GlobalJsonResponseBody;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/account")
public class AccountController {
    private final AccountService accountService;
    private final ClientRegistrationRepository clientRegistrationRepository;

    // Create an account
    @PostMapping
    public ResponseEntity<GlobalJsonResponseBody> createAccount(@Valid @RequestBody CreateAccountRequestBody requestBody) {
        System.out.println("Creating account with request body: " + requestBody.getAccountName());
        return ResponseEntity.ok(accountService.createAccount(requestBody));
    }

    // Verify an account by email
    @GetMapping("/verify")
    public ResponseEntity<GlobalJsonResponseBody> verifyAccountByEmail(@RequestParam String token) throws VerificationException {
        return ResponseEntity.ok(accountService.verifyAccountByEmail(token));
    }

    //Request password reset link
    @GetMapping("/password-reset-request")
    public ResponseEntity<GlobalJsonResponseBody> requestPasswordReset(@Valid @RequestParam String email) {
        GlobalJsonResponseBody response = accountService.sendPasswordResetLink(email);
        return ResponseEntity.ok(response);
    }

    // Update password
    @PostMapping("/password-reset")
    public ResponseEntity<GlobalJsonResponseBody> resetPassword(@Valid @RequestBody ResetPasswordRequestBody requestBody) throws VerificationException {
        GlobalJsonResponseBody response = accountService.resetPassword(requestBody);
        return ResponseEntity.ok(response);
    }

    //Login
    @PostMapping("/login")
    public ResponseEntity<GlobalJsonResponseBody> login(@Valid @RequestBody LoginRequestBody requestBody) {
        return ResponseEntity.ok(accountService.login(requestBody));
    }

    //Resend verification link
    @GetMapping("/resend-verification")
    public ResponseEntity<GlobalJsonResponseBody> resendVerificationLink(@RequestParam String email) {
        return ResponseEntity.ok(accountService.resendVerificationLink(email));
    }


    @GetMapping("/authorization/{provider}")
    public ResponseEntity<String> getAuthorizationUrl(@PathVariable String provider,
                                                      @RequestParam String redirectUri) {
        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId(provider);
        if (registration == null) {
            return ResponseEntity.badRequest().body("Unknown provider: " + provider);
        }

        // Encode redirectUri for state parameter
        String state = generateState(redirectUri);

        String authUrl = registration.getProviderDetails().getAuthorizationUri() +
                "?client_id=" + registration.getClientId() +
                "&redirect_uri=" + registration.getRedirectUri() +
                "&scope=" + String.join(",", registration.getScopes()) +
                "&response_type=code" +
                "&state=" + state;

        return ResponseEntity.ok(authUrl);
    }

    private String generateState(String redirectUri) {
        return Base64.getEncoder().encodeToString(redirectUri.getBytes());
    }


}
