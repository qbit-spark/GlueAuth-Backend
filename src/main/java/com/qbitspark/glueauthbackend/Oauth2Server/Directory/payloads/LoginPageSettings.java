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
public class LoginPageSettings {
    private String title;
    private String subtitle;
    private String backgroundImageUrl;
    private boolean showSignupLink;
    private boolean showForgotPasswordLink;
    private String termsUrl;
    private String privacyUrl;
    private boolean showSocialButtons;
    private SocialButtonsLayout socialButtonsLayout;

    public enum SocialButtonsLayout {
        VERTICAL,
        HORIZONTAL
    }

    public static LoginPageSettings getDefaults() {
        return LoginPageSettings.builder()
                .title("Welcome")
                .subtitle("Sign in to your account")
                .backgroundImageUrl("")
                .showSignupLink(true)
                .showForgotPasswordLink(true)
                .termsUrl("")
                .privacyUrl("")
                .showSocialButtons(true)
                .socialButtonsLayout(SocialButtonsLayout.VERTICAL)
                .build();
    }
}
