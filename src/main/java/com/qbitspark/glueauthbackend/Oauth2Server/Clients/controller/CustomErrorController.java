package com.qbitspark.glueauthbackend.Oauth2Server.Clients.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequiredArgsConstructor
public class CustomErrorController implements ErrorController {
    private static final Logger logger = LoggerFactory.getLogger(CustomErrorController.class);

    // Generic error handler (catches Spring Boot's /error endpoint)
    @RequestMapping("/error")
    public ModelAndView handleError(HttpServletRequest request) {
        // Get error details from request attributes
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        Object exception = request.getAttribute(RequestDispatcher.ERROR_EXCEPTION);
        String message = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);

        int statusCode = 500; // Default to internal server error
        if (status != null) {
            statusCode = Integer.parseInt(status.toString());
        }

        // Log error details
        logger.error("Error occurred: status={}, message={}, exception={}",
                statusCode, message, exception);

        // Prepare custom error page
        ModelAndView mav = new ModelAndView("error-page");

        // Set appropriate error title and message based on status
        switch (statusCode) {
            case 404:
                mav.addObject("errorTitle", "Page Not Found");
                mav.addObject("errorMessage", "The requested page could not be found.");
                break;
            case 403:
                mav.addObject("errorTitle", "Access Denied");
                mav.addObject("errorMessage", "You don't have permission to access this resource.");
                break;
            case 401:
                mav.addObject("errorTitle", "Authentication Required");
                mav.addObject("errorMessage", "Authentication is required to access this resource.");
                break;
            default:
                mav.addObject("errorTitle", "Unexpected Error");
                mav.addObject("errorMessage", "An unexpected error occurred. Please try again later.");
                break;
        }

        mav.addObject("statusCode", statusCode);

        return mav;
    }

    // OAuth2-specific error handler
    @GetMapping("/oauth2/error")
    public ModelAndView handleOAuth2Error(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "error_description", required = false) String errorDescription) {

        // Log OAuth2 error
        logger.error("OAuth2 error: {}, description: {}", error, errorDescription);

        ModelAndView mav = new ModelAndView("error-page");
        mav.addObject("errorTitle", "OAuth 2.0 Error");
        mav.addObject("statusCode", HttpStatus.BAD_REQUEST.value());

        // Set appropriate error message based on error code
        String errorMessage = "An error occurred during the OAuth 2.0 authorization process.";
        if (error != null) {
            switch (error) {
                case "invalid_request":
                    errorMessage = "The request is missing a required parameter or is otherwise malformed.";
                    break;
                case "unauthorized_client":
                    errorMessage = "The client is not authorized to request an authorization code using this method.";
                    break;
                case "access_denied":
                    errorMessage = "The resource owner denied the request.";
                    break;
                case "unsupported_response_type":
                    errorMessage = "The authorization server does not support obtaining an authorization code using this method.";
                    break;
                case "invalid_scope":
                    errorMessage = "The requested scope is invalid, unknown, or malformed.";
                    break;
                case "server_error":
                    errorMessage = "The authorization server encountered an unexpected condition.";
                    break;
                case "temporarily_unavailable":
                    errorMessage = "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance.";
                    break;
                case "invalid_client":
                    errorMessage = "Client authentication failed.";
                    break;
                case "invalid_grant":
                    errorMessage = "The provided authorization grant or refresh token is invalid, expired, or revoked.";
                    break;
            }
        }

        mav.addObject("errorMessage", errorMessage);
        mav.addObject("oauth2Error", error);
        mav.addObject("oauth2ErrorDescription", errorDescription);

        return mav;
    }

    // Access denied error handler
    @GetMapping("/access-denied")
    public ModelAndView handleAccessDenied() {
        ModelAndView mav = new ModelAndView("error-page");
        mav.addObject("errorTitle", "Access Denied");
        mav.addObject("statusCode", HttpStatus.FORBIDDEN.value());
        mav.addObject("errorMessage", "You don't have permission to access this resource.");
        return mav;
    }
}