package com.qbitspark.glueauthbackend.DeveloperService.Auth.utils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

@Component
public class CookieUtils {

    @Value("${app.cookie.domain:localhost}")
    private String cookieDomain;

    @Value("${app.cookie.secured:false}")
    private boolean isSecured;

    @Value("${app.cookie.access-token.expiry-seconds:604800}")
    private int accessTokenExpirySeconds;

    @Value("${app.cookie.refresh-token.expiry-seconds:31536000}")
    private int refreshTokenExpirySeconds;

    @Value("${app.cookie.same-site:Lax}")
    private String sameSite;

    private static final String ACCESS_TOKEN_COOKIE_NAME = "access_token";
    private static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";

    public void addAccessTokenCookie(HttpServletResponse response, String token) {
        // Only use the header approach for setting cookies
        String cookieHeaderValue = String.format("%s=%s; Max-Age=%d; Path=/; Domain=%s; HttpOnly; %sSameSite=%s",
                ACCESS_TOKEN_COOKIE_NAME,
                token,
                accessTokenExpirySeconds,
                cookieDomain,
                isSecured ? "Secure; " : "",
                sameSite);

        response.addHeader("Set-Cookie", cookieHeaderValue);
    }

    public void addRefreshTokenCookie(HttpServletResponse response, String token) {
        // Only use the header approach for setting cookies
        String cookieHeaderValue = String.format("%s=%s; Max-Age=%d; Path=/; Domain=%s; HttpOnly; %sSameSite=%s",
                REFRESH_TOKEN_COOKIE_NAME,
                token,
                refreshTokenExpirySeconds,
                cookieDomain,
                isSecured ? "Secure; " : "",
                sameSite);

        response.addHeader("Set-Cookie", cookieHeaderValue);
    }

    public void clearTokenCookies(HttpServletResponse response) {
        // Only use the header approach for clearing cookies
        String accessCookieHeaderValue = String.format("%s=; Max-Age=0; Path=/; Domain=%s; HttpOnly; %sSameSite=%s",
                ACCESS_TOKEN_COOKIE_NAME,
                cookieDomain,
                isSecured ? "Secure; " : "",
                sameSite);

        String refreshCookieHeaderValue = String.format("%s=; Max-Age=0; Path=/; Domain=%s; HttpOnly; %sSameSite=%s",
                REFRESH_TOKEN_COOKIE_NAME,
                cookieDomain,
                isSecured ? "Secure; " : "",
                sameSite);

        response.addHeader("Set-Cookie", accessCookieHeaderValue);
        response.addHeader("Set-Cookie", refreshCookieHeaderValue);
    }

    public Optional<String> getAccessTokenFromCookies(HttpServletRequest request) {
        return getCookieValue(request, ACCESS_TOKEN_COOKIE_NAME);
    }

    public Optional<String> getRefreshTokenFromCookies(HttpServletRequest request) {
        return getCookieValue(request, REFRESH_TOKEN_COOKIE_NAME);
    }

    private Cookie createCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(isSecured);
        cookie.setPath("/");
        cookie.setDomain(cookieDomain);
        cookie.setMaxAge(maxAge);

        // Set SameSite attribute - requires Servlet 5.0+ or custom approach
        // In Jakarta Servlet 5.0+, you can use the following:
        // cookie.setAttribute("SameSite", sameSite);

        // For now, we'll set it using a response header in the methods that add cookies

        return cookie;
    }

    private Optional<String> getCookieValue(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();


        if (cookies == null) {
            return Optional.empty();
        }

        return Arrays.stream(cookies)
                .filter(cookie -> name.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findAny();
    }
}