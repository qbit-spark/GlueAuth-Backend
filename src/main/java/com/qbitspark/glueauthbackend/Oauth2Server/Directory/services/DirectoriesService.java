package com.qbitspark.glueauthbackend.Oauth2Server.Directory.services;

import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.payloads.CreateDirectoryRequest;

public interface DirectoriesService {
    DirectoryEntity createDirectory(CreateDirectoryRequest request);
}
