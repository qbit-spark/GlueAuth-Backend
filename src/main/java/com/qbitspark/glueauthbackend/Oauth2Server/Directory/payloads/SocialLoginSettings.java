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
public class SocialLoginSettings {
    private boolean enabled;
    private List<String> providers;

    public static SocialLoginSettings getDefaults() {
        return SocialLoginSettings.builder()
                .enabled(true)
                .providers(List.of("GOOGLE", "GITHUB"))
                .build();
    }
}
