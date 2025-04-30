package com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RefreshTokenRequestBody {
    @NotBlank(message = "Refresh token should not be empty")
    String refreshToken;
}
