package com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.jwt;

import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.repos.DirectoryRepo;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.DirectoryUserEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.repo.DirectoryUserRepo;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Service that provides directory-aware OIDC user information.
 * This service extracts directory context from authorization objects
 * and returns user information scoped to that specific directory.
 */
@Service
@RequiredArgsConstructor
public class DirectoryAwareOidcUserInfoService {

    private final DirectoryUserRepo directoryUserRepo;
    private final DirectoryRepo directoryRepo;

    /**
     * Create user information for OIDC responses with directory context.
     *
     * @param username The username
     * @param directoryId The directory ID
     * @return OidcUserInfo object containing user claims scoped to their directory
     */
    public OidcUserInfo createUserInfo(String username, UUID directoryId) {
        // Find directory
        DirectoryEntity directory = directoryRepo.findById(directoryId).orElse(null);
        if (directory == null) {
            return null;
        }

        // Find user in this specific directory
        DirectoryUserEntity user = directoryUserRepo.findByUsernameAndDirectory(username, directory)
                .orElse(null);

        if (user == null) {
            return null;
        }

        // Build claims map
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", username);
        claims.put("email", user.getEmail());
        claims.put("email_verified", user.isEmailVerified());

        if (user.getFirstName() != null) {
            claims.put("given_name", user.getFirstName());
        }

        if (user.getLastName() != null) {
            claims.put("family_name", user.getLastName());
        }

        if (user.getDisplayName() != null) {
            claims.put("name", user.getDisplayName());
        } else if (user.getFirstName() != null && user.getLastName() != null) {
            claims.put("name", user.getFirstName() + " " + user.getLastName());
        }

        if (user.getPhoneNumber() != null) {
            claims.put("phone_number", user.getPhoneNumber());
            claims.put("phone_number_verified", user.isPhoneVerified());
        }

        // Add directory context
        claims.put("directory_id", directoryId.toString());
        claims.put("directory_name", directory.getName());

        // Add updated_at if available
        if (user.getUpdatedAt() != null) {
            claims.put("updated_at", user.getUpdatedAt().toEpochSecond(ZoneOffset.UTC));
        }

        return new OidcUserInfo(claims);
    }
}