package com.qbitspark.glueauthbackend.Oauth2Server.Clients.payload;

import lombok.Data;

import java.util.UUID;

@Data
public class RegisterClientRequest {
    private String clientName;
    private String authorizationGrantType;
    private String redirectUri;
    private boolean requireProofKey;
    private String tokenFormat;
    private UUID directoryId;

}
