package com.qbitspark.glueauthbackend.DeveloperService.Auth.controllers;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.repos.AccountRepo;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.utils.CookieUtils;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.TokenExpiredException;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.TokenInvalidException;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeResponseBody.GlobalJsonResponseBody;

import com.qbitspark.glueauthbackend.DeveloperService.GlobeSecurity.JWTProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class TokenRefreshController {

    private final JWTProvider jwtProvider;
    private final CookieUtils cookieUtil;
    private final AccountRepo accountRepo;

    @PostMapping("/refresh")
    public ResponseEntity<GlobalJsonResponseBody> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) throws Exception {

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
}