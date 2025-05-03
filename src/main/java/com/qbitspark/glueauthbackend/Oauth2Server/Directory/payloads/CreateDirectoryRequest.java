package com.qbitspark.glueauthbackend.Oauth2Server.Directory.payloads;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.Map;

@Data
public class CreateDirectoryRequest {
    @NotBlank(message = "Directory name cannot be blank")
    private String name;
    private String description;
    private Map<String, Object> settings;
}
