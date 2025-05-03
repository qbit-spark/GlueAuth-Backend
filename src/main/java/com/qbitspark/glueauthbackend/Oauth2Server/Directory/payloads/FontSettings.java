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
public class FontSettings {
    private String primary; // Main font for UI
    private String headings; // Font for headings
    private int baseSize; // Base font size in pixels

    public static FontSettings getDefaults() {
        return FontSettings.builder()
                .primary("'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif")
                .headings("'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif")
                .baseSize(16)
                .build();
    }
}
