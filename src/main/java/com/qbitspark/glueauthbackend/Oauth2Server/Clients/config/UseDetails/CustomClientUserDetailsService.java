package com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.UseDetails;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.repos.AccountRepo;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.entities.ClientAppEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.repos.ClientAppRepo;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.DirectoryUserEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.repo.DirectoryUserRepo;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.stream.Collectors;

@Service("oauth2UserDetailsService")
@RequiredArgsConstructor
public class CustomClientUserDetailsService implements UserDetailsService {
    private final DirectoryUserRepo directoryUserRepo;
    private final ClientAppRepo clientAppRepo;
    private final AccountRepo accountRepo;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        // Get client ID from session using RequestContextHolder
//        ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
//        if (attr == null) {
//            throw new UsernameNotFoundException("No request context available");
//        }
//
//        HttpSession session = attr.getRequest().getSession(false);
//        if (session == null) {
//            throw new UsernameNotFoundException("No session available");
//        }
//
//        String clientId = (String) session.getAttribute("CLIENT_ID");
//
//        System.out.println("🚨🚨🚨🚨 This is client Id :"+ clientId);
//
//        if (clientId == null) {
//            throw new UsernameNotFoundException("No client context found in session");
//        }
//
//        // Find a client app
//        ClientAppEntity clientApp = clientAppRepo.findByClientId(clientId)
//                .orElseThrow(() -> new UsernameNotFoundException("Invalid client: " + clientId));
//
//        // Get directory from the client app
//        DirectoryEntity directory = clientApp.getDirectory();
//
//        // Find the user in the directory
//        DirectoryUserEntity user = directoryUserRepo.findByUsernameAndDirectory(username, directory)
//                .orElseThrow(() -> new UsernameNotFoundException("User not found in directory"));

        DirectoryUserEntity user = directoryUserRepo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                //.disabled(!user.isLocked())
                .disabled(false)
                .authorities(
                        user.getRoles().stream()
                                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                                .collect(Collectors.toList())
                )
                .build();
    }
}
