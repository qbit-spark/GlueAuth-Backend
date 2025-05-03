package com.qbitspark.glueauthbackend.Oauth2Server.Directory.payloads;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticationSettings {
    private PasswordPolicy passwordPolicy;
    private boolean mfaEnabled;
    private int loginAttempts;
    private int lockoutDuration; // minutes

    public static AuthenticationSettings getDefaults() {
        return AuthenticationSettings.builder()
                .passwordPolicy(PasswordPolicy.getDefaults())
                .mfaEnabled(false)
                .loginAttempts(5)
                .lockoutDuration(15)
                .build();
    }
}
