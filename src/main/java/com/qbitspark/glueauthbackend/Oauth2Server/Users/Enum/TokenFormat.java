package com.qbitspark.glueauthbackend.Oauth2Server.Users.Enum;

public enum TokenFormat {
    JWT,            // JSON Web Token
    OPAQUE,         // Opaque token (reference token)
    JWT_NESTED      // Nested JWT
}