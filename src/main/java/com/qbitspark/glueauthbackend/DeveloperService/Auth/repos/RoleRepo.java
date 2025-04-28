package com.qbitspark.glueauthbackend.DeveloperService.Auth.repos;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountRoles;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepo extends JpaRepository<AccountRoles, UUID> {
    Optional<AccountRoles> findByRoleName(String roleName);

}
