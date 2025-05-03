package com.qbitspark.glueauthbackend.Oauth2Server.Users.repo;

import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.DirectoryUserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface DirectoryUserRepo extends JpaRepository<DirectoryUserEntity, String> {

    List<DirectoryUserEntity> findAllByDirectory(DirectoryEntity directory);

    DirectoryUserEntity findByUsername(String username);

    DirectoryUserEntity findByEmail(String email);

    DirectoryUserEntity findByPhoneNumber(String phoneNumber);

    void deleteById(String id);

}
