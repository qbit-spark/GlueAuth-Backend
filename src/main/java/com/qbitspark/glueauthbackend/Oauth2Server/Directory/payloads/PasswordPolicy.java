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
public class PasswordPolicy {
    private int minLength;
    private boolean requireLowercase;
    private boolean requireUppercase;
    private boolean requireNumbers;
    private boolean requireSpecialChars;

    public static PasswordPolicy getDefaults() {
        return PasswordPolicy.builder()
                .minLength(8)
                .requireLowercase(true)
                .requireUppercase(true)
                .requireNumbers(true)
                .requireSpecialChars(false)
                .build();
    }
}
