package com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class AccountExistenceException extends UsernameNotFoundException {
    public AccountExistenceException(String message){
        super(message);
    }
}
