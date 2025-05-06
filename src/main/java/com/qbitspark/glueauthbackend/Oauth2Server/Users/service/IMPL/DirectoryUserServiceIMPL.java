package com.qbitspark.glueauthbackend.Oauth2Server.Users.service.IMPL;

import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.repos.DirectoryRepo;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.DirectoryUserEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.payloads.DirectoryUserRequest;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.repo.DirectoryUserRepo;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.service.DirectoryUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

@RequiredArgsConstructor
@Service
public class DirectoryUserServiceIMPL implements DirectoryUserService {

    private final DirectoryUserRepo directoryUserRepo;
    private final DirectoryRepo directoryRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public DirectoryUserEntity save(DirectoryUserRequest request) {

        // FInd the directory by ID
        DirectoryEntity directory = directoryRepo.findById(request.getDirectoryId()).orElseThrow(
                () -> new NoSuchElementException("Directory not found")
        );

        // Check if this username already exists in the directory, then return null
        if (directoryUserRepo.existsByUsernameAndDirectory(generateUserName(request.getEmail()), directory)) {
            System.out.println("-------User already exists in the directory-------------");
            return null;
        }

        // Create a new DirectoryUserEntity
        DirectoryUserEntity directoryUserEntity = new DirectoryUserEntity();
        directoryUserEntity.setEmail(request.getEmail());
        directoryUserEntity.setPassword(passwordEncoder.encode(request.getPassword()));
        directoryUserEntity.setUsername(generateUserName(request.getEmail()));
        directoryUserEntity.setDirectory(directory);

        return directoryUserRepo.save(directoryUserEntity);
    }

    @Override
    public DirectoryUserEntity findByUsername(String username) {
        return null;
    }

    @Override
    public DirectoryUserEntity findByEmail(String email) {
        return null;
    }

    @Override
    public DirectoryUserEntity findByPhoneNumber(String phoneNumber) {
        return null;
    }

    @Override
    public DirectoryUserEntity findById(UUID id) {
        return directoryUserRepo.findById(id).orElseThrow(
                () -> new NoSuchElementException("User not found")
        );
    }


    @Override
    public void deleteById(String id) {

    }

    @Override
    public void updateUser(DirectoryUserEntity directoryUserEntity) {

    }

    @Override
    public List<DirectoryUserEntity> findAll() {
        return directoryUserRepo.findAll();
    }

    @Override
    public List<DirectoryUserEntity> findAllByDirectoryId(UUID directoryId) {
        DirectoryEntity directory = directoryRepo.findById(directoryId).orElseThrow(
                () -> new NoSuchElementException("Directory not found")
        );
        return directoryUserRepo.findAllByDirectory(directory);
    }

    //generate username from email
    private String generateUserName(String email) {

        StringBuilder username = new StringBuilder();
        for (int i = 0; i < email.length(); i++) {
            char c = email.charAt(i);
            if (c != '@') {
                username.append(c);
            } else {
                break;
            }
        }
        return username.toString();
    }
}
