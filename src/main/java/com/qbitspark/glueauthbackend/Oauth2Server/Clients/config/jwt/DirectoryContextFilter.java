package com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.jwt;

import com.qbitspark.glueauthbackend.Oauth2Server.Clients.utils.DirectoryContextHolder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger logger = LoggerFactory.getLogger(DirectoryContextFilter.class);

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        try {
            // Try to get directory_id from request parameter (GET)
            String directoryIdStr = request.getParameter("directory_id");

            // If not found in parameters, check if this is a POST form submission
            if ((directoryIdStr == null || directoryIdStr.isEmpty()) && "POST".equals(request.getMethod())) {
                directoryIdStr = request.getParameter("directory_id");
                logger.debug("Looking for directory ID in POST form data: {}", directoryIdStr);
            }

            // Also check for directory_id in a header (for API calls)
            if (directoryIdStr == null || directoryIdStr.isEmpty()) {
                directoryIdStr = request.getHeader("X-Directory-ID");
                logger.debug("Looking for directory ID in header: {}", directoryIdStr);
            }

            if (directoryIdStr != null && !directoryIdStr.isEmpty()) {
                try {
                    UUID directoryId = UUID.fromString(directoryIdStr);
                    DirectoryContextHolder.setDirectoryId(directoryId);
                    logger.info("Directory ID set in context filter: {}", directoryId);
                } catch (IllegalArgumentException e) {
                    logger.warn("Invalid directory ID format: {}", directoryIdStr);
                }
            } else {
                logger.debug("No directory_id found in request");
            }

            filterChain.doFilter(request, response);
        } finally {
            // Always clear the context after the request is processed
            DirectoryContextHolder.clear();
        }
    }
}