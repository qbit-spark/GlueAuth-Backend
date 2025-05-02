package com.qbitspark.glueauthbackend.Oauth2Server.Users.Enum;

public enum IdentityType {
    // Password-based auth methods
    EMAIL_PASSWORD,     // Traditional email + password
    USERNAME_PASSWORD,  // Username + password
    PHONE_PASSWORD,     // Phone + password

    // Passwordless methods
    MAGIC_LINK,         // Email magic link
    MAGIC_CODE,         // Email one-time code
    PHONE_OTP,          // SMS one-time password

    // External identity providers
    SOCIAL_LOGIN        // Social identity provider login
}
