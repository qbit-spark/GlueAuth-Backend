package com.qbitspark.glueauthbackend.Oauth2Server.Users.payloads;

import lombok.Data;

import java.util.UUID;

@Data
public class DirectoryUserRequest {
    private String email;
    private String password;
    private UUID directoryId;
}
