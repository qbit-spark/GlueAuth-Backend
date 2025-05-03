package com.qbitspark.glueauthbackend.Oauth2Server.Directory.repos;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface DirectoryRepo extends JpaRepository<DirectoryEntity, UUID> {
    List<DirectoryEntity> findDirectoryEntitiesByOwner(AccountEntity owner);
    Optional<DirectoryEntity> findDirectoryEntityById(UUID id);
    boolean existsDirectoryEntitiesByOwnerAndName(AccountEntity owner, String name);
    Optional<DirectoryEntity> findDirectoryEntityByIdAndOwner(UUID id, AccountEntity owner);
}
