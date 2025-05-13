package com.qbitspark.glueauthbackend.Oauth2Server.Clients.payload;

import com.qbitspark.glueauthbackend.Oauth2Server.enums.ApplicationType;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Data
public class RegisterClientRequest {
    @NotNull(message = "Client name cannot be blank")
    private String clientName;
    private Set<String> redirectUris = new HashSet<>();
    @NotNull(message = "Directory ID cannot be blank")
    private UUID directoryId;
    @NotNull(message = "Application type cannot be blank")
    private ApplicationType applicationType;
}