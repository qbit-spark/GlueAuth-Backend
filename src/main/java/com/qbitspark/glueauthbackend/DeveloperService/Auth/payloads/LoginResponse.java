package com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads;

import lombok.Data;

@Data
public class LoginResponse {
    private Object userData;
    private String accessToken;
    private String refreshToken;
}
