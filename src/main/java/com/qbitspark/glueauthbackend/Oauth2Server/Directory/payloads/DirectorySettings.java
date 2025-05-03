package com.qbitspark.glueauthbackend.Oauth2Server.Directory.payloads;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DirectorySettings {
    private AuthenticationSettings authentication;
    private SessionSettings session;
    private SocialLoginSettings socialLogin;
    private EmailSettings email;
    private BrandingSettings branding;

    public static DirectorySettings getDefaults() {
        return DirectorySettings.builder()
                .authentication(AuthenticationSettings.getDefaults())
                .session(SessionSettings.getDefaults())
                .socialLogin(SocialLoginSettings.getDefaults())
                .email(EmailSettings.getDefaults())
                .branding(BrandingSettings.getDefaults())
                .build();
    }
}

