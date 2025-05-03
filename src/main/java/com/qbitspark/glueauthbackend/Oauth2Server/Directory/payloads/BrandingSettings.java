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
public class BrandingSettings {
    private String logoUrl;
    private String faviconUrl;
    private ColorSettings colors;
    private FontSettings fonts;
    private CustomCssSettings customCss;
    private LoginPageSettings loginPage;

    public static BrandingSettings getDefaults() {
        return BrandingSettings.builder()
                .logoUrl("")
                .faviconUrl("")
                .colors(ColorSettings.getDefaults())
                .fonts(FontSettings.getDefaults())
                .customCss(CustomCssSettings.getDefaults())
                .loginPage(LoginPageSettings.getDefaults())
                .build();
    }
}

