package com.qbitspark.glueauthbackend.Oauth2Server.Users.repo;

import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.DirectoryUserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface DirectoryUserRepo extends JpaRepository<DirectoryUserEntity, UUID> {

    List<DirectoryUserEntity> findAllByDirectory(DirectoryEntity directory);

    boolean existsByUsernameAndDirectory(String username, DirectoryEntity directory);

    Optional<DirectoryUserEntity> findByUsername(String username);

    Optional<DirectoryUserEntity> findByUsernameAndDirectory(String username, DirectoryEntity directory);

    Optional<DirectoryUserEntity> findByEmailAndDirectory(String email, DirectoryEntity directory);

    DirectoryUserEntity findByPhoneNumber(String phoneNumber);

    List<DirectoryUserEntity> findAllByUsername(String username);
    List<DirectoryUserEntity> findAllByEmail(String email);

}
