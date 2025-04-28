package com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions;

public class TokenInvalidSignatureException extends Exception{
    public TokenInvalidSignatureException(String message){
        super(message);
    }
}
