package com.qbitspark.glueauthbackend.Oauth2Server.Directory.repos;

import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface DirectoryRepo extends JpaRepository<DirectoryEntity, UUID> {
}
