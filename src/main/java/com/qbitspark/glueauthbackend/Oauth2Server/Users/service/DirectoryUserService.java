package com.qbitspark.glueauthbackend.Oauth2Server.Users.service;

import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.DirectoryUserEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.payloads.DirectoryUserRequest;

import java.util.List;
import java.util.UUID;

public interface DirectoryUserService {

    DirectoryUserEntity findByUsername(String username);

    DirectoryUserEntity findByEmail(String email);

    DirectoryUserEntity findByPhoneNumber(String phoneNumber);

    DirectoryUserEntity findById(UUID id);

    DirectoryUserEntity save(DirectoryUserRequest request);

    void deleteById(String id);

    void updateUser(DirectoryUserEntity directoryUserEntity);

    List<DirectoryUserEntity> findAll();

    List<DirectoryUserEntity> findAllByDirectoryId(UUID directoryId);

}
