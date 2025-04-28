package com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions;

public class TokenEmptyException extends Exception{
    public TokenEmptyException(String message){
        super(message);
    }
}
