package com.qbitspark.glueauthbackend.Oauth2Server.enums;


/**
 * Authentication methods supported for OAuth 2.0 clients.
 * Based on RFC 7591, RFC 7523, RFC 7616, and OpenID Connect standards.
 */
public enum AuthenticationMethod {
    /**
     * Client authenticates with its client_id and client_secret using HTTP Basic Authentication.
     */
    CLIENT_SECRET_BASIC,

    /**
     * Client authenticates by including its client_id and client_secret in the request body.
     */
    CLIENT_SECRET_POST,

    /**
     * Client authenticates with a JWT signed with a private key.
     * The corresponding public key is registered with the server.
     */
    PRIVATE_KEY_JWT,

    /**
     * No authentication is performed for this client (public client).
     */
    NONE,

    /**
     * Client authenticates with its client_id and a client_secret using JWT Bearer Token.
     */
    CLIENT_SECRET_JWT,

    /**
     * Client authenticates using mutual TLS (mTLS) with X.509 certificates.
     */
    TLS_CLIENT_AUTH,

    /**
     * Client attests to its identity via a Self-Signed Certificate.
     */
    SELF_SIGNED_TLS_CLIENT_AUTH,

    /**
     * Client uses a password digest for authentication (using algorithms like SHA-256).
     */
    CLIENT_SECRET_DIGEST
}