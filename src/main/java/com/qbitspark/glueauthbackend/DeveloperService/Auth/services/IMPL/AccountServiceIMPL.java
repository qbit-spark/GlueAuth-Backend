package com.qbitspark.glueauthbackend.DeveloperService.Auth.services.IMPL;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountRoles;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.VerificationTokenEntity;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.AccountType;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.SubscriptionStatus;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.SubscriptionTier;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.VerificationType;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads.*;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.repos.AccountRepo;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.repos.RoleRepo;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.repos.VerificationTokenRepo;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.services.AccountService;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.AccountExistenceException;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.TokenInvalidException;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeAdvice.Exceptions.VerificationException;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeEmailService.EmailService;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeResponseBody.GlobalJsonResponseBody;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeSecurity.JWTProvider;
import jakarta.transaction.Transactional;
import jakarta.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


@Service
@RequiredArgsConstructor
public class AccountServiceIMPL implements AccountService {

    @Value("${glue.auth.email.verify-frontend.base.uri}")
    private String emailVerificationBaseUri;

    private final AccountRepo accountRepo;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepo roleRepo;
    private final VerificationTokenRepo verificationTokenRepo;
    private final EmailService emailService;
    private final JWTProvider tokenProvider;
    private final AuthenticationManager authenticationManager;

    @Transactional
    @Override
    public GlobalJsonResponseBody createAccount(CreateAccountRequestBody requestBody) {
        //Todo: Validate request body
        //Todo: Check if account already exists
        if (accountRepo.existsByEmailAndUsername(requestBody.getEmail(), generateUserName(requestBody.getEmail()))) {
            throw new AccountExistenceException("Account with given email already exists, please login");
        }
        //Todo: Create account user details is personal details or organization details
        AccountEntity accountToBeSaved = generateObjectBasedOnAccountType(requestBody);
        AccountEntity savedAccount = accountRepo.save(accountToBeSaved);
        //Todo: Generate verification link for email
        String verificationLink = generateVerificationToken(savedAccount, VerificationType.EMAIL_VERIFICATION, 30, 1, "/verify-email");
        //Todo: Send verification email
        emailService.sendAccountVerificationEmail(savedAccount.getEmail(), verificationLink);

        return generateSuccessResponseBody("Account created successfully, please verify your email", "Account created successfully, please verify your email", HttpStatus.CREATED);
    }

    @Override
    public GlobalJsonResponseBody login(LoginRequestBody loginRequestBody) {
        //Todo: Validate request body
        if (loginRequestBody.getEmail() == null || loginRequestBody.getEmail().trim().isEmpty()) {
            throw new ValidationException("Email is required");
        }

        if (loginRequestBody.getPassword() == null || loginRequestBody.getPassword().trim().isEmpty()) {
            throw new ValidationException("Password is required");
        }
        //Todo: Check if account exists
        AccountEntity account = accountRepo.findByEmailAndUsername(loginRequestBody.getEmail(), generateUserName(loginRequestBody.getEmail())).orElseThrow(() -> new AccountExistenceException("Account not found"));
        //Todo: Check if account is verified
        if (!account.isEmailVerified()) {
            throw new AccountExistenceException("Account not verified");
        }
        //Todo: Check if account is active
        if (!account.isActive()) {
            throw new AccountExistenceException("Account is not active");
        }
        //Todo: Check if account is locked
        if (account.isLocked()) {
            throw new AccountExistenceException("Account is locked");
        }
        //Todo: Generate token
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        account.getUsername(),
                        loginRequestBody.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String accessToken = tokenProvider.generateAccessToken(authentication);
        String refreshToken = tokenProvider.generateRefreshToken(authentication);

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setAccessToken(accessToken);
        loginResponse.setRefreshToken(refreshToken);
        loginResponse.setUserData(account);

        return generateSuccessResponseBody("Login successful", loginResponse, HttpStatus.OK);
    }


    @Transactional
    @Override
    public GlobalJsonResponseBody verifyAccountByEmail(String token) throws VerificationException {

        //Todo: Check if token is exist
        VerificationTokenEntity verificationToken = verificationTokenRepo.findByToken(token).orElseThrow(() -> new VerificationException("Invalid token"));
        //Todo: Check if token is valid and if token is used and is expired
        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            //If token is expired remove it
            verificationTokenRepo.delete(verificationToken);
            return generateSuccessResponseBody("Token expired", "Token expired", HttpStatus.BAD_REQUEST);
        }

        //Todo: Set account as verified
        AccountEntity account = verificationToken.getAccount();
        account.setEmailVerified(true);
        accountRepo.save(account);
        //Todo: Delete token after use (In case update expired and usage failed to  update)
        verificationTokenRepo.delete(verificationToken);


        //Todo: Generate access and refresh tokens
        Authentication authentication = new UsernamePasswordAuthenticationToken(account.getUsername(), null);
        String accessToken = tokenProvider.generateAccessToken(authentication);
        String refreshToken = tokenProvider.generateRefreshToken(authentication);

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setAccessToken(accessToken);
        loginResponse.setRefreshToken(refreshToken);
        loginResponse.setUserData(account);

        return generateSuccessResponseBody("Account verified successfully", loginResponse, HttpStatus.OK);
    }

    @Transactional
    @Override
    public GlobalJsonResponseBody sendPasswordResetLink(String email) {
        //Todo: validate if given input is email using regex

        // Find an account by email
        AccountEntity account = accountRepo.findByEmail(email)
                .orElseThrow(() -> new AccountExistenceException("No account found with this email"));

        // Generate reset link
        String resetLink = generateVerificationToken(account, VerificationType.PASSWORD_RESET, 30, 1, "/reset-password");

        // Send password reset email
        emailService.sendPasswordResetEmail(account.getEmail(), resetLink);

        return generateSuccessResponseBody("Password reset link sent", "A password reset link has been sent to your email address", HttpStatus.OK);
    }

    @Transactional
    @Override
    public GlobalJsonResponseBody resetPassword(ResetPasswordRequestBody requestBody) throws VerificationException {
        // Validate request body
        if (requestBody.getToken() == null || requestBody.getToken().isEmpty()) {
            throw new ValidationException("Invalid verification token");
        }

        if (requestBody.getNewPassword() == null || requestBody.getNewPassword().isEmpty()) {
            throw new ValidationException("New password cannot be empty");
        }

        if (!requestBody.getNewPassword().equals(requestBody.getConfirmPassword())) {
            throw new ValidationException("New password and confirm password do not match");
        }

        // Find token
        VerificationTokenEntity verificationToken = verificationTokenRepo.findByToken(requestBody.getToken())
                .orElseThrow(() -> new VerificationException("Invalid or expired token"));

        // Validate token type and status
        if (verificationToken.getVerificationType() != VerificationType.PASSWORD_RESET) {
            throw new VerificationException("Invalid token type");
        }

        if (!verificationToken.isValid()) {
            verificationTokenRepo.delete(verificationToken);
            throw new VerificationException("Token has expired or already been used");
        }

        // Get account and update password
        AccountEntity account = verificationToken.getAccount();
        account.setPasswordHash(passwordEncoder.encode(requestBody.getNewPassword()));
        accountRepo.save(account);

        // Mark token as used
        verificationToken.setUsed(true);
        verificationToken.setUsedAt(LocalDateTime.now());
        verificationTokenRepo.save(verificationToken);
        // Delete token after use
        verificationTokenRepo.delete(verificationToken);

        return generateSuccessResponseBody(
                "Password reset successful",
                "Your password has been reset successfully",
                HttpStatus.OK
        );
    }

    @Transactional
    @Override
    public GlobalJsonResponseBody resendVerificationLink(String email) {
        // Validate email is not null or empty
        if (email == null || email.trim().isEmpty()) {
            return generateSuccessResponseBody("Email is required", "Please provide a valid email address", HttpStatus.BAD_REQUEST);
        }

        // Validate email format using regex
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
        if (!Pattern.compile(emailRegex).matcher(email).matches()) {
            throw new ValidationException("Invalid email format");
        }

        // Find an account by email
        AccountEntity account = accountRepo.findByEmail(email)
                .orElseThrow(() -> new AccountExistenceException("No account found with this email"));

        // Check if an account is already verified
        if (account.isEmailVerified()) {
            throw new AccountExistenceException("Account already verified, please login");
        }

        // Check if an account is locked
        if (account.isLocked()) {
            throw new AccountExistenceException("Account is locked, please contact support");
        }

        // Generate a new verification link
        String verificationLink = generateVerificationToken(account, VerificationType.EMAIL_VERIFICATION, 30, 24, "/verify-email");

        // Send the verification email
        emailService.sendAccountVerificationEmail(account.getEmail(), verificationLink);

        return generateSuccessResponseBody("Verification link sent", "A new verification link has been sent to your email address", HttpStatus.OK);

    }


    @Override
    public GlobalJsonResponseBody getAccountById(UUID accountId) {
        return null;
    }

    @Override
    public GlobalJsonResponseBody updateAccount(UUID accountId, UpdateAccountRequestBody requestBody) {
        return null;
    }

    @Override
    public GlobalJsonResponseBody deleteAccount(UUID accountId) {
        return null;
    }


    @Override
    public GlobalJsonResponseBody getAllAccounts() {
        return null;
    }

    @Override
    public GlobalJsonResponseBody getAccountByEmail(String email) {
        return null;
    }

    @Override
    public GlobalJsonResponseBody refreshToken(String refreshToken) throws Exception {
        // Validate refresh token
        if (!tokenProvider.validToken(refreshToken, "REFRESH")) {
            throw new TokenInvalidException("Invalid token");
        }

        // Get username from a token
        String userName = tokenProvider.getUserName(refreshToken);

        // Retrieve user from database
        AccountEntity user = accountRepo.findByUsername(userName)
                .orElseThrow(() -> new AccountExistenceException("Account associated to refresh token not exist"));


        // Create authentication with user authorities
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                user.getUsername(),
                null,
                mapRolesToAuthorities(user.getRoles())
        );

        // Generate only a new token,
        String newAccessToken = tokenProvider.generateAccessToken(authentication);
        String newRefreshToken = tokenProvider.generateRefreshToken(authentication);


        // Build response
        RefreshTokenResponse refreshTokenResponse = new RefreshTokenResponse();
        refreshTokenResponse.setNewToken(newAccessToken);
        refreshTokenResponse.setRefreshToken(newRefreshToken);


        return generateSuccessResponseBody("Token refreshed successfully", refreshTokenResponse, HttpStatus.OK);
    }

    //generate response body
    private GlobalJsonResponseBody generateSuccessResponseBody(String message, Object data, HttpStatus statusCode) {
        return new GlobalJsonResponseBody(
                true,
                statusCode,
                message,
                LocalDateTime.now(),
                data
        );
    }

    //generate username from email
    private String generateUserName(String email) {

        StringBuilder username = new StringBuilder();
        for (int i = 0; i < email.length(); i++) {
            char c = email.charAt(i);
            if (c != '@') {
                username.append(c);
            } else {
                break;
            }
        }
        return username.toString();
    }

    private AccountEntity generateObjectBasedOnAccountType(CreateAccountRequestBody requestBody) {
        AccountEntity account = new AccountEntity();


        account.setEmail(requestBody.getEmail());
        account.setUsername(generateUserName(requestBody.getEmail()));

        if (requestBody.getPassword() != null && !requestBody.getPassword().isEmpty()) {
            account.setPasswordHash(passwordEncoder.encode(requestBody.getPassword()));
        } else {
            // Social login case
            account.setSocialLoginProvider(requestBody.getSocialLoginProvider());
            account.setSocialLoginId(requestBody.getSocialLoginId());
        }

        // Set account type and related fields
        account.setAccountType(requestBody.getAccountType());

        // Use accountName from request or default to username if not provided
        String accountName = requestBody.getAccountName();
        account.setAccountName(accountName != null && !accountName.isEmpty() ?
                accountName : account.getUsername());

        // Handle organization-specific fields if this is an organization account
        if (requestBody.getAccountType() == AccountType.ORGANIZATION) {
            // Validate organization fields
            if (requestBody.getOrganizationName() == null || requestBody.getOrganizationName().trim().isEmpty()) {
                throw new IllegalArgumentException("Organization name is required for organization accounts");
            }

            if (requestBody.getOrganizationSize() == null) {
                throw new IllegalArgumentException("Organization size is required for organization accounts");
            }

            account.setOrganizationName(requestBody.getOrganizationName());
            account.setOrganizationSize(requestBody.getOrganizationSize());
        }

        // Set additional fields from the request
        account.setProfilePictureUrl(requestBody.getProfilePictureUrl());
        account.setPhoneNumber(requestBody.getPhoneNumber());

        // Set default values for new accounts
        account.setEmailVerified(false);
        account.setPhoneVerified(false);
        account.setTwoFactorEnabled(false);
        account.setActive(true);
        account.setLocked(false);

        // Set default subscription tier
        account.setSubscriptionTier(SubscriptionTier.FREE);
        account.setSubscriptionStatus(SubscriptionStatus.ACTIVE);

        Set<AccountRoles> roles = new HashSet<>();
        AccountRoles accountRoles = roleRepo.findByRoleName("ROLE_DEVELOPER").get();
        roles.add(accountRoles);
        account.setRoles(roles);


        return account;
    }

    private String generateVerificationToken(
            AccountEntity account,
            VerificationType verificationType,
            int tokenLength,
            int expirationHours,
            String urlPath) {

        // Generate random token
        String randomToken = RandomStringUtils.randomAlphanumeric(tokenLength);

        // Check if there's an existing token for this account and verification type
        VerificationTokenEntity existingToken = verificationTokenRepo
                .findVerificationTokenEntitiesByAccountAndVerificationType(account, verificationType);

        if (existingToken != null) {
            // If a token already exists, update it
            existingToken.setToken(randomToken);
            existingToken.setCreatedAt(LocalDateTime.now());
            existingToken.setExpiresAt(LocalDateTime.now().plusHours(expirationHours));
            existingToken.setUsed(false);
            existingToken.setUsedAt(null);
            verificationTokenRepo.save(existingToken);
        } else {
            // Create a new token
            VerificationTokenEntity newToken = new VerificationTokenEntity();
            newToken.setAccount(account);
            newToken.setToken(randomToken);
            newToken.setVerificationType(verificationType);
            newToken.setCreatedAt(LocalDateTime.now());
            newToken.setExpiresAt(LocalDateTime.now().plusHours(expirationHours));
            newToken.setUsed(false);
            verificationTokenRepo.save(newToken);
        }

        // Generate verification link
        return emailVerificationBaseUri + urlPath + "?token=" + randomToken;
    }

    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Set<AccountRoles> roles) {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getRoleName()))
                .collect(Collectors.toList());
    }
}
