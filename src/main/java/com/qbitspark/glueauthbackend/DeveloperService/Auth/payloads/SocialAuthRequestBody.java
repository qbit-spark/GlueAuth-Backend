package com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.SocialProviders;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class SocialAuthRequestBody {
    private String code;
    private SocialProviders provider;
}
