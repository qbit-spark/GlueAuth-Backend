package com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions;

public class PermissionDeniedException extends Exception{
    public PermissionDeniedException(String message){
        super(message);
    }
}
