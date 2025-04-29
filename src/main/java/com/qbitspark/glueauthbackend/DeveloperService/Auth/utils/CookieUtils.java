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

    @Value("${app.cookie.domain:}")
    private String cookieDomain;

    @Value("${app.cookie.secure:true}")
    private boolean secureCookie;

    @Value("${app.cookie.http-only:true}")
    private boolean httpOnlyCookie;

    @Value("${app.access-token.expiration:3600}")
    private int accessTokenExpiration;

    @Value("${app.refresh-token.expiration:2592000}")
    private int refreshTokenExpiration;

    /**
     * Create a cookie with the provided name and value
     */
    public Cookie createCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(httpOnlyCookie);
        cookie.setSecure(secureCookie);
        cookie.setMaxAge(maxAge);

        if (!cookieDomain.isEmpty()) {
            cookie.setDomain(cookieDomain);
        }

        return cookie;
    }

    /**
     * Add access token and refresh token as cookies
     */
    public void addAuthCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        // Set access token cookie
        Cookie accessTokenCookie = createCookie("access_token", accessToken, accessTokenExpiration);
        response.addCookie(accessTokenCookie);

        // Set refresh token cookie
        Cookie refreshTokenCookie = createCookie("refresh_token", refreshToken, refreshTokenExpiration);
        response.addCookie(refreshTokenCookie);
    }

    /**
     * Get a cookie by name
     */
    public Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }

        return Arrays.stream(request.getCookies())
                .filter(cookie -> name.equals(cookie.getName()))
                .findFirst();
    }

    /**
     * Get the access token from the cookies
     */
    public Optional<String> getAccessToken(HttpServletRequest request) {
        return getCookie(request, "access_token")
                .map(Cookie::getValue);
    }

    /**
     * Get the refresh token from the cookies
     */
    public Optional<String> getRefreshToken(HttpServletRequest request) {
        return getCookie(request, "refresh_token")
                .map(Cookie::getValue);
    }

    /**
     * Clear the authentication cookies
     */
    public void clearAuthCookies(HttpServletResponse response) {
        Cookie accessTokenCookie = createCookie("access_token", "", 0);
        Cookie refreshTokenCookie = createCookie("refresh_token", "", 0);

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
    }
}