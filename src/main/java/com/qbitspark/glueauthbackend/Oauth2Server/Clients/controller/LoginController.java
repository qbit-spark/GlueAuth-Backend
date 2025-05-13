package com.qbitspark.glueauthbackend.Oauth2Server.Clients.controller;

import com.qbitspark.glueauthbackend.Oauth2Server.Clients.entities.ClientAppEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.repos.ClientAppRepo;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.service.ClientAppService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.net.URI;
import java.net.URISyntaxException;

@Controller
@RequiredArgsConstructor
public class LoginController {
    private static final Logger logger = LoggerFactory.getLogger(LoginController.class);

    private final ClientAppService clientAppService;
    private final ClientAppRepo clientAppRepo;

    @GetMapping("/custom-login")
    public ModelAndView login(
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "device_code", required = false) String deviceCode,
            @RequestParam(name = "error", required = false) String error,
            @RequestParam(name = "code", required = false) String errorCode,
            HttpServletRequest request) {

        // Initialize model and view
        ModelAndView mav = new ModelAndView("custom-login");

        // Get client_id from request parameters or from saved request
        if (clientId == null) {
            // Try to get it from the saved request
            SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, null);
            if (savedRequest != null) {
                String savedUrl = savedRequest.getRedirectUrl();
                clientId = extractClientId(savedUrl);
            }
        }

        // Store in session if available
        if (clientId != null) {
            request.getSession().setAttribute("CLIENT_ID", clientId);
            logger.debug("Stored client_id in session: {}", clientId);

            // Look up the client name for display
            try {
                ClientAppEntity clientApp = clientAppRepo.getClientNameByClientId(clientId);
                String clientName = clientApp.getClientName();
                if (clientName != null) {
                    mav.addObject("clientName", clientName);
                }
            } catch (Exception e) {
                logger.warn("Could not retrieve client name for ID: {}", clientId, e);
            }
        } else {
            logger.debug("No client_id available to store in session");
        }

        // Store device code if available
        if (deviceCode != null) {
            request.getSession().setAttribute("DEVICE_CODE", deviceCode);
            logger.debug("Stored device_code in session: {}", deviceCode);
        }

        // Add parameters to model
        mav.addObject("clientId", clientId);
        mav.addObject("deviceCode", deviceCode);

        return mav;
    }

    // Helper method to safely extract client_id from URL
    private String extractClientId(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }

        try {
            URI uri = new URI(url);
            String query = uri.getQuery();
            if (query == null || query.isEmpty()) {
                return null;
            }

            String[] params = query.split("&");
            for (String param : params) {
                String[] keyValue = param.split("=");
                if (keyValue.length == 2 && "client_id".equals(keyValue[0])) {
                    return keyValue[1];
                }
            }
        } catch (URISyntaxException e) {
            logger.warn("Failed to parse URL for client_id extraction: {}", url, e);
        }

        return null;
    }
}