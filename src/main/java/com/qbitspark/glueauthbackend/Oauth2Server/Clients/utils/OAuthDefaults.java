package com.qbitspark.glueauthbackend.Oauth2Server.Clients.utils;

import com.qbitspark.glueauthbackend.Oauth2Server.enums.*;

import java.util.EnumMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Utility class to determine default OAuth 2.0 settings based on application type
 */
public class OAuthDefaults {

    // Maps ApplicationType to ClientsTypes
    private static final Map<ApplicationType, ClientsTypes> clientTypeMap = new EnumMap<>(ApplicationType.class);

    // Maps ApplicationType to recommended GrantTypes
    private static final Map<ApplicationType, Set<GrantType>> grantTypeMap = new EnumMap<>(ApplicationType.class);

    // Maps ApplicationType to recommend AuthenticationMethods
    private static final Map<ApplicationType, Set<AuthenticationMethod>> authMethodMap = new EnumMap<>(ApplicationType.class);

    // Maps ApplicationType to recommend TokenType
    private static final Map<ApplicationType, TokenType> tokenTypeMap = new EnumMap<>(ApplicationType.class);

    static {
        // Initialize client type mappings
        clientTypeMap.put(ApplicationType.WEB_APP, ClientsTypes.CONFIDENTIAL);
        clientTypeMap.put(ApplicationType.SINGLE_PAGE_APP, ClientsTypes.PUBLIC);
        clientTypeMap.put(ApplicationType.NATIVE_APP, ClientsTypes.PUBLIC);
        clientTypeMap.put(ApplicationType.MACHINE_TO_MACHINE, ClientsTypes.CONFIDENTIAL);
        clientTypeMap.put(ApplicationType.DEVICE_APP, ClientsTypes.PUBLIC);

        // Initialize grant type mappings with REFRESH_TOKEN added to appropriate app types

        // WEB_APP applications
        Set<GrantType> webGrants = new HashSet<>();
        webGrants.add(GrantType.AUTH_CODE_FLOW);
        webGrants.add(GrantType.REFRESH_TOKEN);
        grantTypeMap.put(ApplicationType.WEB_APP, webGrants);

        // SINGLE_PAGE_APP applications
        Set<GrantType> spaGrants = new HashSet<>();
        spaGrants.add(GrantType.AUTH_CODE_WITH_PKCE);
        spaGrants.add(GrantType.REFRESH_TOKEN);
        grantTypeMap.put(ApplicationType.SINGLE_PAGE_APP, spaGrants);

        // NATIVE_APP applications
        Set<GrantType> nativeGrants = new HashSet<>();
        nativeGrants.add(GrantType.AUTH_CODE_WITH_PKCE);
        nativeGrants.add(GrantType.REFRESH_TOKEN);
        grantTypeMap.put(ApplicationType.NATIVE_APP, nativeGrants);

        // MACHINE_TO_MACHINE applications
        Set<GrantType> m2mGrants = new HashSet<>();
        m2mGrants.add(GrantType.CLIENT_CREDENTIALS);
        // M2M typically doesn't use refresh tokens as it uses long-lived access tokens but lets add it for flexibility
        m2mGrants.add(GrantType.REFRESH_TOKEN);
        grantTypeMap.put(ApplicationType.MACHINE_TO_MACHINE, m2mGrants);

        // DEVICE_APP applications
        Set<GrantType> deviceGrants = new HashSet<>();
        deviceGrants.add(GrantType.DEVICE_FLOW);
        deviceGrants.add(GrantType.REFRESH_TOKEN);
        grantTypeMap.put(ApplicationType.DEVICE_APP, deviceGrants);

        // Initialize authentication method mappings

        // WEB_APP applications
        Set<AuthenticationMethod> webAuthMethods = new HashSet<>();
        webAuthMethods.add(AuthenticationMethod.CLIENT_SECRET_BASIC);
        webAuthMethods.add(AuthenticationMethod.CLIENT_SECRET_POST);
        authMethodMap.put(ApplicationType.WEB_APP, webAuthMethods);

        // SINGLE_PAGE_APP applications
        Set<AuthenticationMethod> spaAuthMethods = new HashSet<>();
        spaAuthMethods.add(AuthenticationMethod.NONE);
        authMethodMap.put(ApplicationType.SINGLE_PAGE_APP, spaAuthMethods);

        // NATIVE_APP applications
        Set<AuthenticationMethod> nativeAuthMethods = new HashSet<>();
        nativeAuthMethods.add(AuthenticationMethod.NONE);
        authMethodMap.put(ApplicationType.NATIVE_APP, nativeAuthMethods);

        // MACHINE_TO_MACHINE applications
        Set<AuthenticationMethod> m2mAuthMethods = new HashSet<>();
        m2mAuthMethods.add(AuthenticationMethod.CLIENT_SECRET_BASIC);
        m2mAuthMethods.add(AuthenticationMethod.CLIENT_SECRET_POST);
        m2mAuthMethods.add(AuthenticationMethod.PRIVATE_KEY_JWT);
        m2mAuthMethods.add(AuthenticationMethod.TLS_CLIENT_AUTH);
        authMethodMap.put(ApplicationType.MACHINE_TO_MACHINE, m2mAuthMethods);

        // DEVICE_APP applications
        Set<AuthenticationMethod> deviceAuthMethods = new HashSet<>();
        deviceAuthMethods.add(AuthenticationMethod.NONE);
        authMethodMap.put(ApplicationType.DEVICE_APP, deviceAuthMethods);

        // Initialize token type mappings
        tokenTypeMap.put(ApplicationType.WEB_APP, TokenType.SELF_CERTIFYING);
        tokenTypeMap.put(ApplicationType.SINGLE_PAGE_APP, TokenType.SELF_CERTIFYING);
        tokenTypeMap.put(ApplicationType.NATIVE_APP, TokenType.SELF_CERTIFYING);
        tokenTypeMap.put(ApplicationType.MACHINE_TO_MACHINE, TokenType.SELF_CERTIFYING);
        tokenTypeMap.put(ApplicationType.DEVICE_APP, TokenType.SELF_CERTIFYING);
    }

    /**
     * Get the recommended client type for an application type
     */
    public static ClientsTypes getClientType(ApplicationType applicationType) {
        return clientTypeMap.getOrDefault(applicationType, ClientsTypes.CONFIDENTIAL);
    }

    /**
     * Get the recommended grant types for an application type
     */
    public static Set<GrantType> getRecommendedGrantTypes(ApplicationType applicationType) {
        return new HashSet<>(grantTypeMap.getOrDefault(applicationType, new HashSet<>()));
    }

    /**
     * Get the recommended authentication methods for an application type
     */
    public static Set<AuthenticationMethod> getRecommendedAuthMethods(ApplicationType applicationType) {
        return new HashSet<>(authMethodMap.getOrDefault(applicationType, new HashSet<>()));
    }

    /**
     * Get the recommended token type for an application type
     */
    public static TokenType getRecommendedTokenType(ApplicationType applicationType) {
        return tokenTypeMap.getOrDefault(applicationType, TokenType.OPAQUE);
    }

    /**
     * Check if the application type should use refresh tokens
     */
    public static boolean shouldUseRefreshTokens(ApplicationType applicationType) {
        Set<GrantType> grantTypes = getRecommendedGrantTypes(applicationType);
        return grantTypes.contains(GrantType.REFRESH_TOKEN);
    }

    /**
     * Check if the application type requires PKCE
     */
    public static boolean requiresPkce(ApplicationType applicationType) {
        Set<GrantType> grantTypes = getRecommendedGrantTypes(applicationType);
        return grantTypes.contains(GrantType.AUTH_CODE_WITH_PKCE);
    }

    /**
     * Validate if the provided grant types are suitable for the application type
     * @return true if the grant types are appropriate for the app type
     */
    public static boolean validateGrantTypesForAppType(ApplicationType appType, Set<GrantType> grantTypes) {
        // For public clients, password and client credentials are not allowed
        if (getClientType(appType) == ClientsTypes.PUBLIC) {
            if (grantTypes.contains(GrantType.PASSWORD) ||
                    grantTypes.contains(GrantType.CLIENT_CREDENTIALS)) {
                return false;
            }
        }

        // Specific application type validations
        switch (appType) {
            case MACHINE_TO_MACHINE:
                // M2M should only use client credentials
                // Allow refresh token as an optional grant type
                return grantTypes.contains(GrantType.CLIENT_CREDENTIALS) &&
                        (grantTypes.size() == 1 ||
                                (grantTypes.size() == 2 && grantTypes.contains(GrantType.REFRESH_TOKEN)));
            case DEVICE_APP:
                // Device apps should use device flow
                return grantTypes.contains(GrantType.DEVICE_FLOW);
            case SINGLE_PAGE_APP:
                // SPAs should use PKCE, not regular auth code flow
                return !grantTypes.contains(GrantType.AUTH_CODE_FLOW) &&
                        grantTypes.contains(GrantType.AUTH_CODE_WITH_PKCE);
            default:
                return true;
        }
    }
}