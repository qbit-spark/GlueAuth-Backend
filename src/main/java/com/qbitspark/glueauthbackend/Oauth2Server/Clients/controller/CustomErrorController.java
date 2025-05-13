package com.qbitspark.glueauthbackend.Oauth2Server.Clients.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class CustomErrorController implements ErrorController {
    private static final Logger logger = LoggerFactory.getLogger(CustomErrorController.class);

    @GetMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        // Get error status
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        String errorMessage = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
        Object exception = request.getAttribute(RequestDispatcher.ERROR_EXCEPTION);

        // Log error details
        logger.error("Error page accessed: status={}, message={}, exception={}",
                status, errorMessage, exception);

        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());

            // Add status code to the model
            model.addAttribute("statusCode", statusCode);

            // Add appropriate error message
            if (statusCode == HttpStatus.NOT_FOUND.value()) {
                model.addAttribute("errorTitle", "Page Not Found");
                model.addAttribute("errorMessage", "The requested page could not be found.");
            } else if (statusCode == HttpStatus.FORBIDDEN.value()) {
                model.addAttribute("errorTitle", "Access Denied");
                model.addAttribute("errorMessage", "You do not have permission to access this resource.");
            } else if (statusCode == HttpStatus.UNAUTHORIZED.value()) {
                model.addAttribute("errorTitle", "Authentication Required");
                model.addAttribute("errorMessage", "You must be logged in to access this resource.");
                return "redirect:/custom-login"; // Redirect to login page
            } else {
                model.addAttribute("errorTitle", "Error Occurred");
                model.addAttribute("errorMessage", errorMessage != null ?
                        errorMessage : "An unexpected error occurred.");
            }
        } else {
            model.addAttribute("errorTitle", "Error Occurred");
            model.addAttribute("errorMessage", "An unexpected error occurred.");
        }

        // Check if OAuth2 error parameters exist
        String oauth2Error = request.getParameter("error");
        if (oauth2Error != null) {
            model.addAttribute("oauth2Error", oauth2Error);
            model.addAttribute("oauth2ErrorDescription", request.getParameter("error_description"));
        }

        return "error-page";
    }

    @GetMapping("/oauth2/error")
    public String handleOAuth2Error(HttpServletRequest request, Model model) {
        String error = request.getParameter("error");
        String errorDescription = request.getParameter("error_description");

        logger.error("OAuth2 error: {}, description: {}", error, errorDescription);

        model.addAttribute("errorTitle", "OAuth 2.0 Error");
        model.addAttribute("statusCode", HttpStatus.BAD_REQUEST.value());
        model.addAttribute("errorMessage", "An error occurred during the OAuth 2.0 authorization process.");
        model.addAttribute("oauth2Error", error);
        model.addAttribute("oauth2ErrorDescription", errorDescription);

        return "error-page";
    }
}