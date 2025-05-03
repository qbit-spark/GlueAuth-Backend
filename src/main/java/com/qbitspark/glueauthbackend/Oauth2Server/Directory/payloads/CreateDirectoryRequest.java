package com.qbitspark.glueauthbackend.Oauth2Server.Directory.payloads;

import lombok.Data;

import java.util.Map;

@Data
public class CreateDirectoryRequest {
    private String name;
    private String description;
    private Map<String, Object> settings;
}
