package com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions;

public class TokenExpiredException extends Exception{
    public TokenExpiredException(String message){
        super(message);
    }
}
