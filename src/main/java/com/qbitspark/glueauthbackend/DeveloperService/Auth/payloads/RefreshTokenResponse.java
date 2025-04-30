package com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads;

import lombok.Data;

@Data
public class RefreshTokenResponse {
    private String newToken;
    private String refreshToken;
}
