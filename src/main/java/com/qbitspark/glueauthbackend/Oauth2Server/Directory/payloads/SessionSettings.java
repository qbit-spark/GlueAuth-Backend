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
public class SessionSettings {
    private int idleTimeout; // minutes
    private int absoluteTimeout; // hours
    private boolean persistentSessions;

    public static SessionSettings getDefaults() {
        return SessionSettings.builder()
                .idleTimeout(30)
                .absoluteTimeout(24)
                .persistentSessions(true)
                .build();
    }
}
