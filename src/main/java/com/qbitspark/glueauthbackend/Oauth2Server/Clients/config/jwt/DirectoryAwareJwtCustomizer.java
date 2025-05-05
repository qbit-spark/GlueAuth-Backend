package com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.jwt;

import com.qbitspark.glueauthbackend.Oauth2Server.Directory.repos.DirectoryRepo;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.utils.DirectoryContextHolder;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class DirectoryAwareJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final DirectoryRepo directoryRepository;

    @Override
    public void customize(JwtEncodingContext context) {
        if (context.getTokenType() == OAuth2TokenType.ACCESS_TOKEN) {
            // Get directory ID from context holder
            UUID directoryId = DirectoryContextHolder.getDirectoryId();
            if (directoryId != null) {
                // Add directory ID claim to token
                context.getClaims().claim("directory_id", directoryId.toString());

                // Add directory name for convenience
                directoryRepository.findById(directoryId).ifPresent(directory ->
                        context.getClaims().claim("directory_name", directory.getName())
                );
            }

            // Add directory-specific roles
            Authentication principal = context.getPrincipal();
            if (principal != null && principal.getAuthorities() != null) {
                Set<String> roles = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .filter(authority -> authority.startsWith("ROLE_"))
                        .map(authority -> authority.substring(5))
                        .collect(Collectors.toSet());

                if (!roles.isEmpty()) {
                    context.getClaims().claim("roles", roles);
                }
            }
        }
    }
}