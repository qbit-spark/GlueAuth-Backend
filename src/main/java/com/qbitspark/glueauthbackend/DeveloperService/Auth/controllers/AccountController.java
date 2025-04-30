package com.qbitspark.glueauthbackend.DeveloperService.Auth.controllers;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads.CreateAccountRequestBody;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads.LoginRequestBody;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads.ResetPasswordRequestBody;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.repos.AccountRepo;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.services.AccountService;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.utils.CookieUtils;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.TokenExpiredException;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.TokenInvalidException;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.VerificationException;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeResponseBody.GlobalJsonResponseBody;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeSecurity.JWTProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/account")
public class AccountController {
    private final AccountService accountService;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final JWTProvider jwtProvider;
    private final CookieUtils cookieUtil;
    private final AccountRepo accountRepo;


    // Create an account
    @PostMapping
    public ResponseEntity<GlobalJsonResponseBody> createAccount(@Valid @RequestBody CreateAccountRequestBody requestBody) {
        System.out.println("Creating account with request body: " + requestBody.getAccountName());
        return ResponseEntity.ok(accountService.createAccount(requestBody));
    }

    // Verify an account by email
    @GetMapping("/verify")
    public ResponseEntity<GlobalJsonResponseBody> verifyAccountByEmail(@RequestParam String token, HttpServletResponse httpServletResponse) throws VerificationException {
        return ResponseEntity.ok(accountService.verifyAccountByEmail(token, httpServletResponse));
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
    public ResponseEntity<GlobalJsonResponseBody> login(@Valid @RequestBody LoginRequestBody requestBody,
                                                        HttpServletResponse response) {

        return ResponseEntity.ok(accountService.login(requestBody, response));
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

    @PostMapping("/refresh")
    public ResponseEntity<GlobalJsonResponseBody> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) throws Exception {

        // Debug: Print all cookies
        Cookie[] cookies = request.getCookies();
        System.out.println("Token refresh request received with cookies:");
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                System.out.println(" - Cookie: " + cookie.getName() + " (present)");
            }
        } else {
            System.out.println(" - No cookies found in request");
        }

        // Get refresh token from cookie
        Optional<String> refreshTokenOpt = cookieUtil.getRefreshTokenFromCookies(request);


        if (refreshTokenOpt.isEmpty()) {
            throw new TokenInvalidException("Refresh token not found");
        }

        String refreshToken = refreshTokenOpt.get();

        // Validate refresh token
        if (!jwtProvider.validToken(refreshToken, "REFRESH")) {
            cookieUtil.clearTokenCookies(response);
            throw new TokenExpiredException("Refresh token is invalid or expired");
        }

        // Get username from token
        String username = jwtProvider.getUserName(refreshToken);

        // Get user by username
        AccountEntity account = accountRepo.findByUsername(username)
                .orElseThrow(() -> new TokenInvalidException("User not found"));

        // Generate new tokens
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                username, null, null);

        String newAccessToken = jwtProvider.generateAccessToken(authentication);
        String newRefreshToken = jwtProvider.generateRefreshToken(authentication);

        // Set tokens as cookies
        cookieUtil.addAccessTokenCookie(response, newAccessToken);
        cookieUtil.addRefreshTokenCookie(response, newRefreshToken);

        GlobalJsonResponseBody responseBody = new GlobalJsonResponseBody();
        responseBody.setSuccess(true);
        responseBody.setHttpStatus(HttpStatus.OK);
        responseBody.setMessage("Token refreshed successfully");
        responseBody.setActionTime(LocalDateTime.now());
        responseBody.setData(account);

        return ResponseEntity.ok(responseBody);
    }

    //Logout
    @PostMapping("/logout")
    public ResponseEntity<GlobalJsonResponseBody> logout(HttpServletRequest request, HttpServletResponse response) {
        // Clear cookies
        cookieUtil.clearTokenCookies(response);


        GlobalJsonResponseBody responseBody = new GlobalJsonResponseBody();
        responseBody.setSuccess(true);
        responseBody.setHttpStatus(HttpStatus.OK);
        responseBody.setMessage("Logged out successfully");
        responseBody.setActionTime(LocalDateTime.now());

        return ResponseEntity.ok(responseBody);
    }

}
