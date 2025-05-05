package com.qbitspark.glueauthbackend.Oauth2Server.Clients.service.IMPL;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.repos.AccountRepo;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.AccountExistenceException;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.entities.ClientAppEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.payload.RegisterClientRequest;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.repos.ClientAppRepo;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.service.ClientAppService;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.repos.DirectoryRepo;
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
import java.util.List;
import java.util.Optional;
import java.util.UUID;

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


        // Create a new client entity
        ClientAppEntity clientEntity = new ClientAppEntity();
        clientEntity.setClientId(clientId);
        clientEntity.setClientSecret(clientSecret);
        clientEntity.setClientName(request.getClientName());
        clientEntity.setRedirectUri(request.getRedirectUri());
        clientEntity.setRequireProofKey(request.isRequireProofKey());
        clientEntity.setAuthorizationGrantType(request.getAuthorizationGrantType());
        clientEntity.setTokenFormat(request.getTokenFormat());
        clientEntity.setDirectory(directory);
        clientEntity.setOwner(loginAccount);


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
        // Determine authorization grant type
        AuthorizationGrantType grantType = "client_credentials".equals(client.getAuthorizationGrantType()) ?
                AuthorizationGrantType.CLIENT_CREDENTIALS : AuthorizationGrantType.AUTHORIZATION_CODE;

        // Determine token format
        OAuth2TokenFormat tokenFormat = "reference".equals(client.getTokenFormat()) ?
                OAuth2TokenFormat.REFERENCE : OAuth2TokenFormat.SELF_CONTAINED;

        // Build the registered client with all settings in one pass
        return RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientName(client.getClientName())
                .clientSecret(passwordEncoder.encode(client.getClientSecret()))
                .redirectUri(client.getRedirectUri())
                .authorizationGrantType(grantType)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(tokenFormat)
                        .accessTokenTimeToLive(Duration.ofHours(12))
                        .build()
                )
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(client.isRequireProofKey())
                        .requireAuthorizationConsent(false)
                        .build())
                .scope("openid")
                .scope("read")
                .scope("write")
                .build();
    }

}
