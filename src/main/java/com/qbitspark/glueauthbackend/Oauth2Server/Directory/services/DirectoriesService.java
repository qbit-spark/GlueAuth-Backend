package com.qbitspark.glueauthbackend.Oauth2Server.Directory.services;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.payloads.CreateDirectoryRequest;

import java.util.List;
import java.util.UUID;

public interface DirectoriesService {
    DirectoryEntity createDirectory(CreateDirectoryRequest request);
    List<DirectoryEntity> getAllDirectories();
    List<DirectoryEntity> getAllDirectoriesByAccount(AccountEntity account);
    DirectoryEntity getDirectoryById(UUID id);
    DirectoryEntity getDirectoryByIdAndAccount(UUID id);
    List<DirectoryEntity> getDirectoriesByLoginAccount();
}
