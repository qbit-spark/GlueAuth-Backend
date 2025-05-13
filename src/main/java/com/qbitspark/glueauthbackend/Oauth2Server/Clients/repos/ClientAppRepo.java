package com.qbitspark.glueauthbackend.Oauth2Server.Clients.repos;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.entities.ClientAppEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ClientAppRepo extends JpaRepository<ClientAppEntity, UUID> {
    Optional<ClientAppEntity> findByClientId(String clientId);
    Optional<ClientAppEntity> findById(String id);
    List<ClientAppEntity> findAllByDirectoryAndOwner(DirectoryEntity directory, AccountEntity owner);
    boolean existsByClientNameAndDirectory(String clientName, DirectoryEntity directory);
    ClientAppEntity getClientNameByClientId(String clientId);
}
