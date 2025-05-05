package com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.jwt;

import com.qbitspark.glueauthbackend.Oauth2Server.Clients.utils.DirectoryContextHolder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Filter that extracts directory ID from requests and sets it in thread-local context.
 * Directory ID can be provided in:
 * 1. Request parameter "directory_id"
 * 2. Request header "X-Directory-ID"
 * 3. URL path for REST endpoints in the format "/directories/{directoryId}/..."
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class DirectoryContextFilter extends OncePerRequestFilter {

    private static final Pattern PATH_PATTERN = Pattern.compile("/directories/([a-f0-9-]+)/");

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        try {
            // Try to get directory_id from request parameter
            String directoryIdStr = request.getParameter("directory_id");

            if (directoryIdStr != null && !directoryIdStr.isEmpty()) {
                try {
                    UUID directoryId = UUID.fromString(directoryIdStr);
                    DirectoryContextHolder.setDirectoryId(directoryId);
                    // Log successful directory context setting
                    System.out.println("🚨🚨🚨 Directory ID set from request parameter: " + directoryId);
                } catch (IllegalArgumentException e) {
                    System.out.println("Invalid directory ID format in request parameter: " + directoryIdStr);
                }
            } else {
                logger.debug("No directory_id parameter found in request");
            }

            filterChain.doFilter(request, response);
        } finally {
            // Always clear the context after the request is processed
            DirectoryContextHolder.clear();
        }
    }

    private void extractFromParameter(HttpServletRequest request) {
        String directoryParam = request.getParameter("directory_id");
        if (directoryParam != null && !directoryParam.isEmpty()) {
            try {
                UUID directoryId = UUID.fromString(directoryParam);
                DirectoryContextHolder.setDirectoryId(directoryId);
                System.out.println("🚨🚨🚨 Directory ID set from request parameter: " + directoryId);
            } catch (IllegalArgumentException e) {
                System.out.println("Invalid directory ID format in request parameter: " + directoryParam);
            }
        }
    }

    private void extractFromHeader(HttpServletRequest request) {
        String directoryHeader = request.getHeader("X-Directory-ID");
        if (directoryHeader != null && !directoryHeader.isEmpty()) {
            try {
                UUID directoryId = UUID.fromString(directoryHeader);
                DirectoryContextHolder.setDirectoryId(directoryId);
                System.out.println("Directory ID set from request header: " + directoryId);
            } catch (IllegalArgumentException e) {
                System.out.println("Invalid directory ID format in request header: " + directoryHeader);
            }
        }
    }

    private void extractFromPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        Matcher matcher = PATH_PATTERN.matcher(uri);
        if (matcher.find()) {
            try {
                UUID directoryId = UUID.fromString(matcher.group(1));
                DirectoryContextHolder.setDirectoryId(directoryId);
                System.out.println("Directory ID set from URL path: " + directoryId);
            } catch (IllegalArgumentException e) {
                System.out.println("Invalid directory ID format in URL path: " + matcher.group(1));
            }
        }
    }
}