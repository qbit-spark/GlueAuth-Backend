package com.qbitspark.glueauthbackend.DeveloperService.Auth.repos;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.VerificationTokenEntity;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.VerificationType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface VerificationTokenRepo extends JpaRepository<VerificationTokenEntity, UUID> {
    Optional<VerificationTokenEntity> findByToken(String token);

    VerificationTokenEntity findByAccountId(UUID accountId);

    VerificationTokenEntity findByAccountIdAndToken(UUID accountId, String token);

    VerificationTokenEntity findVerificationTokenEntitiesByAccountAndVerificationType(AccountEntity accountEntity, VerificationType verificationType);

}
