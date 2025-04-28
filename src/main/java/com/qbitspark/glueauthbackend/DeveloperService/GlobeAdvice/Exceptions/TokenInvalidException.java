package com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions;

public class TokenInvalidException extends Exception{
    public TokenInvalidException(String message){
        super(message);
    }
}
