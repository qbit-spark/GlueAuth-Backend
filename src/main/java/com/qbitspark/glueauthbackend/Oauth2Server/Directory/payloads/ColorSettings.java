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
public class ColorSettings {
    private String primary; // Main brand color
    private String secondary; // Secondary brand color
    private String accent; // Accent color for highlights
    private String background; // Page background color
    private String text; // Main text color
    private String buttonText; // Button text color

    public static ColorSettings getDefaults() {
        return ColorSettings.builder()
                .primary("#6c5ce7") // Default purple
                .secondary("#a29bfe")
                .accent("#00cec9")
                .background("#ffffff")
                .text("#333333")
                .buttonText("#ffffff")
                .build();
    }
}
