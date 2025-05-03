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
public class CustomCssSettings {
    private boolean enabled;
    private String customCssCode;

    public static CustomCssSettings getDefaults() {
        return CustomCssSettings.builder()
                .enabled(false)
                .customCssCode("")
                .build();
    }
}
