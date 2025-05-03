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
public class EmailSettings {
    private boolean verificationRequired;
    private boolean welcomeEmailEnabled;

    public static EmailSettings getDefaults() {
        return EmailSettings.builder()
                .verificationRequired(true)
                .welcomeEmailEnabled(true)
                .build();
    }
}
