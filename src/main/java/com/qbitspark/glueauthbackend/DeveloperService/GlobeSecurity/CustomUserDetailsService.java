package com.qbitspark.glueauthbackend.DeveloperService.GlobeSecurity;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.repos.AccountRepo;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.ItemReadyExistException;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

@AllArgsConstructor
@Service("apiUserDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    private final AccountRepo accountRepo;

    @SneakyThrows
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        AccountEntity accountUser = accountRepo.findByUsername(username)
                .orElseThrow(() -> new ItemReadyExistException("User with given username not found: " + username));

        Set<GrantedAuthority> authorities =
                accountUser.getRoles()
                        .stream()
                        .map(role -> new SimpleGrantedAuthority(role.getRoleName()))
                        .collect(Collectors.toSet());

        return new User(accountUser.getUsername(),
                accountUser.getPasswordHash(),
                authorities);
    }
}

