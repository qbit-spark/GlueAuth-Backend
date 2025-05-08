package com.qbitspark.glueauthbackend.Oauth2Server.Clients.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequiredArgsConstructor
public class LoginController {

    @GetMapping("/custom-login")
    public ModelAndView login(
            @RequestParam(name = "client_id", required = false) String clientId,
            HttpServletRequest request) {

        // Get client_id from request parameters or from saved request
        if (clientId == null) {
            // Try to get it from the saved request
            SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, null);
            if (savedRequest != null) {
                String savedUrl = savedRequest.getRedirectUrl();
                if (savedUrl != null && savedUrl.contains("client_id=")) {
                    // Extract client_id from the URL
                    String[] parts = savedUrl.split("client_id=");
                    if (parts.length > 1) {
                        String part = parts[1];
                        int endIndex = part.indexOf('&');
                        clientId = endIndex > 0 ? part.substring(0, endIndex) : part;
                    }
                }
            }
        }

        // Store in session if available
        if (clientId != null) {
            request.getSession().setAttribute("CLIENT_ID", clientId);
            System.out.println("Stored client_id in session: " + clientId);
        } else {
            System.out.println("No client_id available to store in session");
        }

        ModelAndView mav = new ModelAndView("custom-login");
        mav.addObject("clientId", clientId); // Also add to model for the form
        return mav;
    }
}