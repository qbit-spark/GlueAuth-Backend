package com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions;

public class AccessDeniedException extends Exception{
    public AccessDeniedException(String message){
        super(message);
    }
}
