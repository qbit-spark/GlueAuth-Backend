package com.qbitspark.glueauthbackend.Oauth2Server.Clients.payload;

import com.qbitspark.glueauthbackend.Oauth2Server.enums.ApplicationType;
import lombok.Data;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Data
public class RegisterClientRequest {
    private String clientName;
    private Set<String> redirectUris = new HashSet<>();
    private UUID directoryId;
    private ApplicationType applicationType;
}