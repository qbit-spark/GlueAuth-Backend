package com.qbitspark.glueauthbackend.Oauth2Server.enums;

public enum GrantType {
    AUTH_CODE_FLOW,           // authorization_code
    AUTH_CODE_WITH_PKCE,      // authorization_code with PKCE
    CLIENT_CREDENTIALS,       // client_credentials
    PASSWORD,                 // password (deprecated)
    DEVICE_FLOW,              // urn:ietf:params:oauth:grant-type:device_code
    JWT_BEARER,               // urn:ietf:params:oauth:grant-type:jwt-bearer
    TOKEN_EXCHANGE,           // urn:ietf:params:oauth:grant-type:token-exchange
    REFRESH_TOKEN             // refresh_token
}