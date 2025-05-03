package com.qbitspark.glueauthbackend.Oauth2Server.Directory.services.IMPL;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.repos.AccountRepo;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.AccountExistenceException;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.payloads.*;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.repos.DirectoryRepo;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.services.DirectoriesService;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.utils.Settings;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class DirectoriesServiceIMPL implements DirectoriesService {

    private final AccountRepo accountRepo;
    private final DirectoryRepo directoryRepo;

    @Override
    @Transactional
    public DirectoryEntity createDirectory(CreateDirectoryRequest request) {
        AccountEntity loginAccount = getAuthenticatedAccount();

        // Check if the directory name already exists for the authenticated user
        if (directoryRepo.existsDirectoryEntitiesByOwnerAndName(loginAccount, request.getName())) {
            throw new AccountExistenceException("Directory with the same name already exists");
        }

        DirectoryEntity directory = new DirectoryEntity();
        directory.setName(request.getName());
        directory.setDescription(request.getDescription());
        directory.setOwner(loginAccount);
        directory.setIsActive(true);

        try {
            ObjectMapper objectMapper = new ObjectMapper();

            // Start with default settings
            DirectorySettings settings = DirectorySettings.getDefaults();

            // Apply any custom settings from the request if provided
            if (request.getSettings() != null) {
                // Deserialize custom settings
                DirectorySettings customSettings = objectMapper.convertValue(
                        request.getSettings(),
                        DirectorySettings.class
                );

                // Apply non-null values from custom settings
               new Settings().mergeSettings(settings, customSettings);
            }

            // Convert settings to JSON string
            directory.setSettings(objectMapper.writeValueAsString(settings));
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize directory settings", e);
            directory.setSettings("{}");
        }

        return directoryRepo.save(directory);
    }

    @Override
    public List<DirectoryEntity> getAllDirectories() {
        return directoryRepo.findAll();
    }

    @Override
    public List<DirectoryEntity> getAllDirectoriesByAccount(AccountEntity account) {
        return directoryRepo.findDirectoryEntitiesByOwner(account);
    }

    @Override
    public DirectoryEntity getDirectoryById(UUID id) {
        return directoryRepo.findDirectoryEntityById(id)
                .orElseThrow(() -> new AccountExistenceException("Directory with given id does not exist"));
    }

    @Override
    public DirectoryEntity getDirectoryByIdAndAccount(UUID id) {
        AccountEntity authenticatedAccount = getAuthenticatedAccount();
        return directoryRepo.findDirectoryEntityByIdAndOwner(id, authenticatedAccount)
                .orElseThrow(() -> new AccountExistenceException("Directory with given id does not exist for this account"));
    }

    @Override
    public List<DirectoryEntity> getDirectoriesByLoginAccount() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        AccountEntity authenticatedAccount = extractAccount(authentication);
        return directoryRepo.findDirectoryEntitiesByOwner(authenticatedAccount);
    }

    private AccountEntity getAuthenticatedAccount() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return extractAccount(authentication);
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

}
