package com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.jwt;

import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.repos.DirectoryRepo;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.utils.DirectoryContextHolder;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.DirectoryUserEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.repo.DirectoryUserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.time.ZoneOffset;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class DirectoryAwareOidcUserInfoMapper implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final DirectoryUserRepo directoryUserRepo;
    private final DirectoryRepo directoryRepo;
    private final DirectoryAwareOidcUserInfoService oidcUserInfoService;

    @Override
    public void customize(JwtEncodingContext context) {
        // Only customize ID tokens
        if (context.getTokenType().getValue().equals("id_token")) {
            // Get directory ID from context
            UUID directoryId = DirectoryContextHolder.getDirectoryId();
            if (directoryId == null) {
                return;
            }

            // Get the principal name from context
            String username = context.getPrincipal().getName();
            if (username == null) {
                return;
            }

            // Find directory
            DirectoryEntity directory = directoryRepo.findById(directoryId).orElse(null);
            if (directory == null) {
                return;
            }

            // Find a user in this specific directory
            DirectoryUserEntity user = directoryUserRepo.findByUsernameAndDirectory(username, directory)
                    .orElse(null);

            if (user != null) {
                // Add standard OIDC claims
                context.getClaims().claim("email", user.getEmail());
                context.getClaims().claim("email_verified", user.isEmailVerified());

                if (user.getFirstName() != null) {
                    context.getClaims().claim("given_name", user.getFirstName());
                }

                if (user.getLastName() != null) {
                    context.getClaims().claim("family_name", user.getLastName());
                }

                if (user.getDisplayName() != null) {
                    context.getClaims().claim("name", user.getDisplayName());
                } else if (user.getFirstName() != null && user.getLastName() != null) {
                    context.getClaims().claim("name", user.getFirstName() + " " + user.getLastName());
                }

                if (user.getPhoneNumber() != null) {
                    context.getClaims().claim("phone_number", user.getPhoneNumber());
                    context.getClaims().claim("phone_number_verified", user.isPhoneVerified());
                }

                // Add directory context
                context.getClaims().claim("directory_id", directoryId.toString());
                context.getClaims().claim("directory_name", directory.getName());

                // Add updated_at if available
                if (user.getUpdatedAt() != null) {
                    context.getClaims().claim("updated_at", user.getUpdatedAt().toEpochSecond(ZoneOffset.UTC));
                }
            }
        }
    }
}