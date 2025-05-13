package com.qbitspark.glueauthbackend.Oauth2Server.Clients.service.IMPL;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.repos.AccountRepo;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.AccountExistenceException;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.entities.ClientAppEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.payload.RegisterClientRequest;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.repos.ClientAppRepo;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.service.ClientAppService;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.utils.OAuthDefaults;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.repos.DirectoryRepo;
import com.qbitspark.glueauthbackend.Oauth2Server.enums.*;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class ClientAppServiceIMPL implements ClientAppService, RegisteredClientRepository {

    private final ClientAppRepo repository;
    private final PasswordEncoder passwordEncoder;
    private final DirectoryRepo directoryRepo;
    private final AccountRepo accountRepo;

    @Transactional
    @Override
    public ClientAppEntity createClientApp(RegisterClientRequest request) {

        AccountEntity loginAccount = getAuthenticatedAccount();

        // Check if the directory exists belong to this user
        DirectoryEntity directory = directoryRepo.findDirectoryEntityByIdAndOwner(request.getDirectoryId(),loginAccount).orElseThrow(
                () -> new AccountExistenceException("Directory with given ID does not exist or does not belong to the user")
        );

        // Check if the client name already exists in the directory
        if (repository.existsByClientNameAndDirectory(request.getClientName(), directory)) {
            throw new AccountExistenceException("Client name already exists in the directory");
        }

        // Generate client ID with a format like "clt_xxxxxxxx"
        String clientId = "clt_" + RandomStringUtils.randomAlphanumeric(28);

        // Generate a more complex client secret
        String clientSecret = RandomStringUtils.randomAlphanumeric(70);

        // Create a client entity
        ClientAppEntity clientEntity = new ClientAppEntity();
        clientEntity.setClientId(clientId);
        clientEntity.setClientName(request.getClientName());
        clientEntity.setDirectory(directory);
        clientEntity.setOwner(loginAccount);

        // Set the creation timestamp and active status
        clientEntity.setCreatedAt(LocalDateTime.now());
        clientEntity.setUpdatedAt(LocalDateTime.now());
        clientEntity.setIsActive(true);

        // Get Application Type and determine the grant type, authentication method, client type
        ApplicationType applicationType = request.getApplicationType();
        clientEntity.setApplicationType(applicationType);

        // Set client type based on application type
        ClientsTypes clientType = OAuthDefaults.getClientType(applicationType);
        clientEntity.setClientType(clientType);

        // Set client secret based on a client type (public clients may not need a secret)
        if (clientType == ClientsTypes.CONFIDENTIAL) {
            clientEntity.setClientSecret(clientSecret);
        } else {
            // For public clients, set null for client secret
            clientEntity.setClientSecret(null);
        }

        // Set recommended grant types
        Set<GrantType> grantTypes = OAuthDefaults.getRecommendedGrantTypes(applicationType);
        clientEntity.setAuthorizationGrantTypes(grantTypes);

        // Set recommended authentication methods
        Set<AuthenticationMethod> authMethods = OAuthDefaults.getRecommendedAuthMethods(applicationType);
        clientEntity.setAuthenticationMethods(authMethods);

        // Set token type based on application type
        TokenType tokenType = OAuthDefaults.getRecommendedTokenType(applicationType);
        clientEntity.setTokenType(tokenType);

        // Set useRefreshTokens flag based on whether REFRESH_TOKEN is in the grant types
        clientEntity.setUseRefreshTokens(grantTypes.contains(GrantType.REFRESH_TOKEN));

        // Set PKCE requirement based on application type
        clientEntity.setRequireProofKey(OAuthDefaults.requiresPkce(applicationType));

        // Set redirect URIs
        if (request.getRedirectUris() != null && !request.getRedirectUris().isEmpty()) {
            clientEntity.setRedirectUris(request.getRedirectUris());
        } else {
            // If no redirect URIs provided, throw an error for authorization code flows
            if (grantTypes.contains(GrantType.AUTH_CODE_FLOW) ||
                    grantTypes.contains(GrantType.AUTH_CODE_WITH_PKCE)) {
                throw new IllegalArgumentException("Redirect URIs are required for authorization code flows");
            }
            // Otherwise set an empty set
            clientEntity.setRedirectUris(new HashSet<>());
        }

        // Save the entity
        return repository.saveAndFlush(clientEntity);
    }

    @Transactional(readOnly = true)
    public List<ClientAppEntity> getAllClientApps() {
        return repository.findAll();
    }

    @Override
    public List<ClientAppEntity> getAllClientAppsByDirectoryId(UUID directoryId) {

        AccountEntity loginAccount = getAuthenticatedAccount();

        return repository.findAllByDirectoryAndOwner(
                directoryRepo.findById(directoryId).orElseThrow(),
                loginAccount
        );
    }

    private AccountEntity getAuthenticatedAccount() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return extractAccount(authentication);
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        // Implementation for saving a registered client
    }

    @Override
    public RegisteredClient findById(String id) {
        return mapToClient(repository.findById(id).orElseThrow());
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return mapToClient(repository.findByClientId(clientId).orElseThrow());
    }

    private AccountEntity extractAccount(Authentication authentication) throws AccountExistenceException {
        if (authentication != null && authentication.isAuthenticated()) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String userName = userDetails.getUsername();

            Optional<AccountEntity> userOptional = accountRepo.findByUsername(userName);
            if (userOptional.isPresent()) {
                return userOptional.get();
            } else {
                throw new AccountExistenceException("User with given userName does not exist");
            }
        } else {
            throw new AccountExistenceException("User is not authenticated");
        }
    }

    private RegisteredClient mapToClient(ClientAppEntity client) {
        // Start building the client
        RegisteredClient.Builder builder = RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientName(client.getClientName());

        // Add a client secret if it exists (for confidential clients)
        if (client.getClientSecret() != null && !client.getClientSecret().isEmpty()) {
            builder.clientSecret(passwordEncoder.encode(client.getClientSecret()));
        }

        // Add redirect URIs
        for (String redirectUri : client.getRedirectUris()) {
            builder.redirectUri(redirectUri);
        }

        // Track if we need to enable PKCE
        boolean requireProofKey = false;

        // Add grant types
        for (GrantType grantType : client.getAuthorizationGrantTypes()) {
            switch (grantType) {
                case AUTH_CODE_FLOW:
                    builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                    break;
                case AUTH_CODE_WITH_PKCE:
                    builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                    // Mark that we need PKCE for this client
                    requireProofKey = true;
                    break;
                case CLIENT_CREDENTIALS:
                    builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
                    break;
                case PASSWORD:
                    builder.authorizationGrantType(AuthorizationGrantType.PASSWORD);
                    break;
                case DEVICE_FLOW:
                    builder.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE);
                    break;
                case JWT_BEARER:
                    builder.authorizationGrantType(AuthorizationGrantType.JWT_BEARER);
                    break;
                case TOKEN_EXCHANGE:
                    builder.authorizationGrantType(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:token-exchange"));
                    break;
                case REFRESH_TOKEN:
                    builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
                    break;
            }
        }

        // Add authentication methods
        for (AuthenticationMethod authMethod : client.getAuthenticationMethods()) {
            switch (authMethod) {
                case CLIENT_SECRET_BASIC:
                    builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                    break;
                case CLIENT_SECRET_POST:
                    builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
                    break;
                case CLIENT_SECRET_JWT:
                    builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
                    break;
                case PRIVATE_KEY_JWT:
                    builder.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
                    break;
                case NONE:
                    builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
                    break;
                case TLS_CLIENT_AUTH:
                    builder.clientAuthenticationMethod(new ClientAuthenticationMethod("tls_client_auth"));
                    break;
                case SELF_SIGNED_TLS_CLIENT_AUTH:
                    builder.clientAuthenticationMethod(new ClientAuthenticationMethod("self_signed_tls_client_auth"));
                    break;
                case CLIENT_SECRET_DIGEST:
                    builder.clientAuthenticationMethod(new ClientAuthenticationMethod("client_secret_digest"));
                    break;
            }
        }

        // Configure token settings
        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder();

        // Set token format based on token type
        if (client.getTokenType() == TokenType.OPAQUE) {
            tokenSettingsBuilder.accessTokenFormat(OAuth2TokenFormat.REFERENCE);
        } else {
            tokenSettingsBuilder.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED);
        }

        // Set token lifetimes
        tokenSettingsBuilder.accessTokenTimeToLive(Duration.ofHours(1));
        if (client.getAuthorizationGrantTypes().contains(GrantType.REFRESH_TOKEN)) {
            tokenSettingsBuilder.refreshTokenTimeToLive(Duration.ofDays(30));
            // Enable refresh token reuse
            tokenSettingsBuilder.reuseRefreshTokens(true);
        }

        builder.tokenSettings(tokenSettingsBuilder.build());

        // Configure client settings
        ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder();

        // If a client uses AUTH_CODE_WITH_PKCE or client.getRequireProofKey() is true, enable PKCE
        if (requireProofKey || client.getRequireProofKey()) {
            clientSettingsBuilder.requireProofKey(true);
        } else {
            clientSettingsBuilder.requireProofKey(false);
        }

        clientSettingsBuilder.requireAuthorizationConsent(false);
        builder.clientSettings(clientSettingsBuilder.build());

        // Add default scopes
        builder.scope("openid")
                .scope("profile")
                .scope("email")
                .scope("read")
                .scope("write");

        return builder.build();
    }
}