package com.qbitspark.glueauthbackend.Oauth2Server.Clients.service.IMPL;

import com.qbitspark.glueauthbackend.Oauth2Server.Clients.utils.DirectoryContextHolder;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.repos.DirectoryRepo;

import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.DirectoryUserEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.repo.DirectoryUserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class DirectoryAwareUserDetailsService implements UserDetailsService {

    private final DirectoryUserRepo directoryUserRepo;
    private final DirectoryRepo directoryRepo;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // Get directory ID from the context holder
        //UUID directoryId = DirectoryContextHolder.getDirectoryId();
        UUID directoryId = UUID.fromString("3e08ac7a-0ff8-4577-a8b0-2fe42e5778bd");
        if (directoryId == null) {
            throw new AuthenticationServiceException("No directory context found");
        }

        // Find directory
        DirectoryEntity directory = directoryRepo.findById(directoryId)
                .orElseThrow(() -> new AuthenticationServiceException("Directory not found"));

        // Find a user in this specific directory
        DirectoryUserEntity user = directoryUserRepo.findByUsernameAndDirectory(username, directory)
                .orElse(null);

        // Try email lookup if username not found (common in SSO flows)
        if (user == null) {
            user = directoryUserRepo.findByEmailAndDirectory(username, directory)
                    .orElseThrow(() -> new UsernameNotFoundException(
                            "User not found in directory: " + directory.getName()));
        }

        // Build authorities (roles) with directory context
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        if (user.getRoles() != null && !user.getRoles().isEmpty()) {
            authorities.addAll(user.getRoles().stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .toList());
        } else {
            authorities.add(new SimpleGrantedAuthority("ROLE_NORMAL_USER"));
        }

        // Add directory-specific authority for authorization checks
        authorities.add(new SimpleGrantedAuthority("DIRECTORY_" + directoryId));

        // Build user details with all account status flags
        return User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .disabled(!user.isEnabled())
                .accountExpired(user.isAccountExpired())
                .accountLocked(!user.isAccountNonLocked())
                .credentialsExpired(user.isCredentialsExpired())
                .authorities(authorities)
                .build();
    }
}