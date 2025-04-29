package com.qbitspark.glueauthbackend.DeveloperService.Auth.Auth2Handler;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.AccountType;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.SocialProviders;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.repos.AccountRepo;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.utils.CookieUtils;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeSecurity.JWTProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AccountRepo accountRepo;
    private final JWTProvider tokenProvider;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final WebClient webClient;
    private final ObjectMapper objectMapper;
    private final CookieUtils cookieUtils;

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauth2User = oauthToken.getPrincipal();
        String registrationId = oauthToken.getAuthorizedClientRegistrationId();

        // Get access token
        String accessToken = getAccessToken(oauthToken);

        // Map registrationId to your SocialProviders enum
        SocialProviders provider = mapRegistrationIdToProvider(registrationId);

        // Extract user info from OAuth2User
        String socialId = Objects.requireNonNull(oauth2User.getAttribute("id")).toString();
        String name = oauth2User.getAttribute("name");
        String pictureUrl = oauth2User.getAttribute("avatar_url");

        // Try to get email, including-from-emails API if needed
        String email = extractEmail(oauth2User, registrationId, accessToken);

        log.info("OAuth login: provider={}, socialId={}, email={}", provider, socialId, email);

        // Find or create an account
        AccountEntity account = findOrCreateAccount(email, socialId, provider, name, pictureUrl);

        // Create our own authentication with JWT
        Authentication customAuth = new UsernamePasswordAuthenticationToken(account.getUsername(), null, null);

        // Generate JWT tokens
        String jwtAccessToken = tokenProvider.generateAccessToken(customAuth);
        String refreshToken = tokenProvider.generateRefreshToken(customAuth);

        // Set character encoding
        response.setCharacterEncoding("UTF-8");

        // Get original redirect from state parameter if available
        String redirectUrl = extractRedirectUrl(request.getParameter("state"));
        boolean isNativeClient = false;

        // Check if this is a native client (indicated by a special redirect URL or param)
        if (redirectUrl != null && redirectUrl.contains("native=true")) {
            isNativeClient = true;
        }

        if (redirectUrl == null || redirectUrl.isEmpty()) {
            // Fallback to default URL
            redirectUrl = determineTargetUrl(request, response, authentication);
        }

        if (isNativeClient) {
            // For native clients, append tokens to the URL
            redirectUrl = appendTokensToUrl(redirectUrl, jwtAccessToken, refreshToken);
        } else {
            // For web clients, set tokens as cookies
            cookieUtils.addAuthCookies(response, jwtAccessToken, refreshToken);
        }

        log.info("Redirecting to: {}", redirectUrl.replaceAll("access_token=.*?(&|$)", "access_token=REDACTED$1"));
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }

    private String getAccessToken(OAuth2AuthenticationToken authentication) {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName());

        return client.getAccessToken().getTokenValue();
    }

    private String extractEmail(OAuth2User oauth2User, String registrationId, String accessToken) {
        if ("github".equals(registrationId)) {
            // Try to get email from user attributes first
            String email = oauth2User.getAttribute("email");

            // If email is null or empty, try to fetch from emails endpoint
            if (email == null || email.isEmpty()) {
                try {
                    log.info("Fetching email from GitHub API");
                    // Make API call to GitHub's email endpoint
                    String response = webClient.get()
                            .uri("https://api.github.com/user/emails")
                            .header("Authorization", "token " + accessToken)
                            .retrieve()
                            .bodyToMono(String.class)
                            .block();

                    // Parse response to find primary email
                    JsonNode emailsNode = objectMapper.readTree(response);

                    if (emailsNode.isArray()) {
                        for (JsonNode emailNode : emailsNode) {
                            // Look for primary and verified email
                            if (emailNode.has("primary") && emailNode.get("primary").asBoolean() &&
                                    emailNode.has("verified") && emailNode.get("verified").asBoolean()) {
                                email = emailNode.get("email").asText();
                                log.info("Found primary verified email: {}", email);
                                break;
                            }
                        }

                        // If no primary verified email found, look for any verified email
                        if (email == null || email.isEmpty()) {
                            for (JsonNode emailNode : emailsNode) {
                                if (emailNode.has("verified") && emailNode.get("verified").asBoolean()) {
                                    email = emailNode.get("email").asText();
                                    log.info("Found verified email: {}", email);
                                    break;
                                }
                            }
                        }

                        // Last resort: take the first email
                        if ((email == null || email.isEmpty()) && emailsNode.size() > 0 && emailsNode.get(0).has("email")) {
                            email = emailsNode.get(0).get("email").asText();
                            log.info("Using first available email: {}", email);
                        }
                    }
                } catch (Exception e) {
                    log.error("Failed to fetch GitHub emails: {}", e.getMessage(), e);
                }
            }

            return email;
        }
        return null;
    }

    private SocialProviders mapRegistrationIdToProvider(String registrationId) {
        if ("github".equals(registrationId)) {
            return SocialProviders.GITHUB;
        }
        // Map other providers as needed
        return null;
    }

    @Transactional
    protected AccountEntity findOrCreateAccount(String email, String socialId, SocialProviders provider, String name, String profilePictureUrl) {
        // Check if an account exists by social ID
        Optional<AccountEntity> existingAccount = accountRepo.findBySocialLoginIdAndSocialAuthProvider(
                socialId, provider);

        if (existingAccount.isPresent()) {
            AccountEntity account = existingAccount.get();

            // Update account info that might have changed
            if (name != null && !name.isEmpty()) {
                account.setAccountName(name);
            }

            if (profilePictureUrl != null && !profilePictureUrl.isEmpty()) {
                account.setProfilePictureUrl(profilePictureUrl);
            }

            // If they previously logged in without email but now have one, update it
            if (email != null && !email.isEmpty() &&
                    (account.getEmail() == null || account.getEmail().endsWith(".user"))) {
                account.setEmail(email);
            }

            account.setLastLogin(LocalDateTime.now());
            return accountRepo.save(account);
        }

        // Check by email
        if (email != null && !email.isEmpty()) {
            Optional<AccountEntity> accountByEmail = accountRepo.findByEmail(email);
            if (accountByEmail.isPresent()) {
                AccountEntity account = accountByEmail.get();
                account.setSocialLoginId(socialId);
                account.setSocialAuthProvider(provider);
                account.setLastLogin(LocalDateTime.now());
                return accountRepo.save(account);
            }
        }

        // Create a new account
        AccountEntity newAccount = new AccountEntity();

        // Handle email
        String userEmail = email;
        if (userEmail == null || userEmail.isEmpty()) {
            userEmail = socialId + "@" + provider.toString().toLowerCase() + ".user";
            log.info("Creating synthetic email: {}", userEmail);
        }
        newAccount.setEmail(userEmail);

        // Generate username safely
        newAccount.setUsername(generateUserName(userEmail));

        newAccount.setSocialLoginId(socialId);
        newAccount.setSocialAuthProvider(provider);
        newAccount.setAccountName(name != null ? name : "GitHub User");
        newAccount.setProfilePictureUrl(profilePictureUrl);
        newAccount.setAccountType(AccountType.PERSONAL);
        newAccount.setEmailVerified(true);
        newAccount.setActive(true);
        newAccount.setLastLogin(LocalDateTime.now());
        newAccount.setCreatedAt(LocalDateTime.now());

        return accountRepo.save(newAccount);
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

    private String appendTokensToUrl(String url, String accessToken, String refreshToken) {
        try {
            String separator = url.contains("?") ? "&" : "?";
            // Use URLEncoder to properly encode the tokens
            String encodedAccessToken = URLEncoder.encode(accessToken, StandardCharsets.UTF_8.toString());
            String encodedRefreshToken = URLEncoder.encode(refreshToken, StandardCharsets.UTF_8.toString());

            // Remove the native flag if present
            String cleanUrl = url.replace("native=true", "").replace("?&", "?").replace("&&", "&");
            if (cleanUrl.endsWith("?") || cleanUrl.endsWith("&")) {
                cleanUrl = cleanUrl.substring(0, cleanUrl.length() - 1);
            }

            return cleanUrl + separator + "access_token=" + encodedAccessToken + "&refresh_token=" + encodedRefreshToken;
        } catch (Exception e) {
            log.error("Error encoding tokens: {}", e.getMessage(), e);

            // Fallback if encoding fails
            String separator = url.contains("?") ? "&" : "?";
            return url + separator + "access_token=" + accessToken + "&refresh_token=" + refreshToken;
        }
    }

    private String extractRedirectUrl(String state) {
        if (state == null || state.isEmpty()) {
            return null;
        }

        try {
            // Use URL-safe Base64 decoding
            return new String(Base64.getUrlDecoder().decode(state), StandardCharsets.UTF_8);
        } catch (Exception e) {
            // If URL-safe decoding fails, try regular Base64 with some pre-processing
            try {
                // Replace URL-unsafe characters and add padding if needed
                String normalized = state
                        .replace('-', '+')
                        .replace('_', '/');

                // Add padding if needed
                while (normalized.length() % 4 != 0) {
                    normalized += "=";
                }

                return new String(Base64.getDecoder().decode(normalized), StandardCharsets.UTF_8);
            } catch (Exception e2) {
                log.warn("Could not decode state parameter: {}", e2.getMessage());
                return null;
            }
        }
    }
}