package com.qbitspark.glueauthbackend.Oauth2Server.Users.service;

import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.DirectoryUserEntity;

import java.util.List;

public interface DirectoryUserService {

    DirectoryUserEntity findByUsername(String username);

    DirectoryUserEntity findByEmail(String email);

    DirectoryUserEntity findByPhoneNumber(String phoneNumber);

    DirectoryUserEntity findById(String id);

    DirectoryUserEntity save(DirectoryUserEntity directoryUserEntity);

    void deleteById(String id);

    void updateUser(DirectoryUserEntity directoryUserEntity);

    List<DirectoryUserEntity> findAll();

    List<DirectoryUserEntity> findAllByDirectoryId(String directoryId);

}
