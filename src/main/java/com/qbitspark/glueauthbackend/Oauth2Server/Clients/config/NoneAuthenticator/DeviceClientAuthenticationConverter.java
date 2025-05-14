package com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.NoneAuthenticator;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.*;

public final class DeviceClientAuthenticationConverter implements AuthenticationConverter {
    private final String deviceAuthorizationEndpointUri;
    private final AuthenticationConverter clientSecretBasicAuthenticationConverter;
    private final Set<String> deviceAuthorizationRequestParameterNames = new HashSet<>(Arrays.asList(
            OAuth2ParameterNames.CLIENT_ID,
            OAuth2ParameterNames.SCOPE
    ));

    public DeviceClientAuthenticationConverter(String deviceAuthorizationEndpointUri) {
        this.deviceAuthorizationEndpointUri = deviceAuthorizationEndpointUri;
        this.clientSecretBasicAuthenticationConverter = new ClientSecretBasicAuthenticationConverter();
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!request.getRequestURI().equals(this.deviceAuthorizationEndpointUri) &&
                !request.getRequestURI().equals("/oauth2/token")) {
            return null;
        }

        // Try basic authentication first (username and password)
        Authentication clientSecretBasicAuthentication = this.clientSecretBasicAuthenticationConverter.convert(request);
        if (clientSecretBasicAuthentication != null) {
            return clientSecretBasicAuthentication;
        }

        // Get client_id from parameters
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId)) {
            return null;
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        // For device authorization request
        if (request.getRequestURI().equals(this.deviceAuthorizationEndpointUri)) {
            // Get scope from parameters
            String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
            if (StringUtils.hasText(scope)) {
                additionalParameters.put(OAuth2ParameterNames.SCOPE, scope);
            }
        } else if (request.getRequestURI().equals("/oauth2/token")) {
            // For token request
            // Get grant_type from parameters
            String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
            if (!StringUtils.hasText(grantType)) {
                return null;
            }
            additionalParameters.put(OAuth2ParameterNames.GRANT_TYPE, grantType);

            // Get device_code from parameters
            String deviceCode = request.getParameter(OAuth2ParameterNames.DEVICE_CODE);
            if (!StringUtils.hasText(deviceCode)) {
                return null;
            }
            additionalParameters.put(OAuth2ParameterNames.DEVICE_CODE, deviceCode);
        }

        // Create an unauthenticated token with client ID and additional parameters
        return new OAuth2ClientAuthenticationToken(
                clientId, ClientAuthenticationMethod.NONE, null, additionalParameters);
    }
}