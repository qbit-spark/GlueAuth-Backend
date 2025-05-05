package com.qbitspark.glueauthbackend.Oauth2Server.Clients.service;

import com.qbitspark.glueauthbackend.Oauth2Server.Clients.entities.ClientAppEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.payload.RegisterClientRequest;

import java.util.List;
import java.util.UUID;

public interface ClientAppService {
    ClientAppEntity createClientApp(RegisterClientRequest request);
    List<ClientAppEntity> getAllClientApps();
    List<ClientAppEntity> getAllClientAppsByDirectoryId(UUID directoryId);
}
