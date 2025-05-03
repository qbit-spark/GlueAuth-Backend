package com.qbitspark.glueauthbackend.Oauth2Server.Users.service.IMPL;

import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.DirectoryUserEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.service.DirectoryUserService;

import java.util.List;

public class DirectoryUserServiceIMPL implements DirectoryUserService {

    @Override
    public DirectoryUserEntity save(DirectoryUserEntity directoryUserEntity) {
        return null;
    }

    @Override
    public DirectoryUserEntity findByUsername(String username) {
        return null;
    }

    @Override
    public DirectoryUserEntity findByEmail(String email) {
        return null;
    }

    @Override
    public DirectoryUserEntity findByPhoneNumber(String phoneNumber) {
        return null;
    }

    @Override
    public DirectoryUserEntity findById(String id) {
        return null;
    }


    @Override
    public void deleteById(String id) {

    }

    @Override
    public void updateUser(DirectoryUserEntity directoryUserEntity) {

    }

    @Override
    public List<DirectoryUserEntity> findAll() {
        return List.of();
    }

    @Override
    public List<DirectoryUserEntity> findAllByDirectoryId(String directoryId) {
        return List.of();
    }
}
