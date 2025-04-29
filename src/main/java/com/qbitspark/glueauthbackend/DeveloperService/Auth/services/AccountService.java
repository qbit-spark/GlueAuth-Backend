package com.qbitspark.glueauthbackend.DeveloperService.Auth.services;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads.*;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.VerificationException;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeResponseBody.GlobalJsonResponseBody;
import jakarta.servlet.http.HttpServletResponse;

import java.util.UUID;

public interface AccountService {
    // Method to create a new account
    GlobalJsonResponseBody createAccount(CreateAccountRequestBody requestBody);

    //Method to login
    GlobalJsonResponseBody login(LoginRequestBody loginRequestBody, HttpServletResponse response);
    // Method to get account details by ID
    GlobalJsonResponseBody getAccountById(UUID accountId);

    // Method to update account details
    GlobalJsonResponseBody updateAccount(UUID accountId, UpdateAccountRequestBody requestBody);


    // Method to delete an account
    GlobalJsonResponseBody deleteAccount(UUID accountId);

    // Method to verify email
    GlobalJsonResponseBody verifyAccountByEmail(String token, HttpServletResponse response) throws VerificationException;

    // Method to send a password-reset link
    GlobalJsonResponseBody sendPasswordResetLink(String email);

    // Method to reset password
    GlobalJsonResponseBody resetPassword(ResetPasswordRequestBody requestBody) throws VerificationException;

    //Resend verification link
    GlobalJsonResponseBody resendVerificationLink(String email);

    // Method to get all accounts
    GlobalJsonResponseBody getAllAccounts();

    // Method to get account by email
    GlobalJsonResponseBody getAccountByEmail(String email);

}
