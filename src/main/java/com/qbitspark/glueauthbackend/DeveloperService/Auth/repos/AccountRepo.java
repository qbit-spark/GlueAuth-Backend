package com.qbitspark.glueauthbackend.DeveloperService.Auth.repos;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.AccountType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface AccountRepo extends JpaRepository<AccountEntity, UUID> {
    Optional<AccountEntity> findByEmail(String email);

    Optional<AccountEntity> findByUsername(String username);

    Optional<AccountEntity> findByEmailAndUsername(String email, String username);

    Optional<AccountEntity> findByAccountName(String accountName);

    Optional<AccountEntity> findByAccountType(AccountType accountType);

    Optional<AccountEntity> findById(UUID id);

    void deleteById(UUID id);

    boolean existsByEmailAndUsername(String email, String username);

}
