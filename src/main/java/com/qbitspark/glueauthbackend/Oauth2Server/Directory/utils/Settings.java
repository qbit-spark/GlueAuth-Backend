package com.qbitspark.glueauthbackend.Oauth2Server.Directory.utils;

import com.qbitspark.glueauthbackend.Oauth2Server.Directory.payloads.*;

import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class Settings {

    public DirectorySettings mergeSettings(DirectorySettings defaults, DirectorySettings custom) {
        if (custom == null) return defaults;

        // Create a builder starting with defaults
        DirectorySettings.DirectorySettingsBuilder builder = DirectorySettings.builder()
                .authentication(defaults.getAuthentication())
                .session(defaults.getSession())
                .socialLogin(defaults.getSocialLogin())
                .email(defaults.getEmail())
                .branding(defaults.getBranding());

        // Override with custom values if they exist
        if (custom.getAuthentication() != null) {
            builder.authentication(mergeAuthSettings(defaults.getAuthentication(), custom.getAuthentication()));
        }

        if (custom.getSession() != null) {
            builder.session(mergeSessionSettings(defaults.getSession(), custom.getSession()));
        }

        if (custom.getSocialLogin() != null) {
            builder.socialLogin(mergeSocialSettings(defaults.getSocialLogin(), custom.getSocialLogin()));
        }

        if (custom.getEmail() != null) {
            builder.email(mergeEmailSettings(defaults.getEmail(), custom.getEmail()));
        }
        if (custom.getBranding() != null) {
            builder.branding(mergeBrandingSettings(defaults.getBranding(), custom.getBranding()));
        }

        return builder.build();
    }

    private AuthenticationSettings mergeAuthSettings(AuthenticationSettings defaults, AuthenticationSettings custom) {
        // Use Builder to create a new object
        AuthenticationSettings.AuthenticationSettingsBuilder builder = AuthenticationSettings.builder();

        // Set defaults first
        builder.mfaEnabled(defaults.isMfaEnabled());
        builder.loginAttempts(defaults.getLoginAttempts());
        builder.lockoutDuration(defaults.getLockoutDuration());

        // Override with custom values (if not null)
        if (custom.isMfaEnabled() != defaults.isMfaEnabled()) {
            builder.mfaEnabled(custom.isMfaEnabled());
        }

        if (custom.getLoginAttempts() > 0) {
            builder.loginAttempts(custom.getLoginAttempts());
        }

        if (custom.getLockoutDuration() > 0) {
            builder.lockoutDuration(custom.getLockoutDuration());
        }

        // For nested objects, call their specific merge method
        if (custom.getPasswordPolicy() != null) {
            builder.passwordPolicy(mergePasswordPolicy(defaults.getPasswordPolicy(), custom.getPasswordPolicy()));
        } else {
            builder.passwordPolicy(defaults.getPasswordPolicy());
        }

        return builder.build();
    }

    private PasswordPolicy mergePasswordPolicy(PasswordPolicy defaults, PasswordPolicy custom) {
        PasswordPolicy.PasswordPolicyBuilder builder = PasswordPolicy.builder();

        // Set defaults
        builder.minLength(defaults.getMinLength());
        builder.requireLowercase(defaults.isRequireLowercase());
        builder.requireUppercase(defaults.isRequireUppercase());
        builder.requireNumbers(defaults.isRequireNumbers());
        builder.requireSpecialChars(defaults.isRequireSpecialChars());

        // Override with custom values
        if (custom.getMinLength() > 0) {
            builder.minLength(custom.getMinLength());
        }

        if (custom.isRequireLowercase() != defaults.isRequireLowercase()) {
            builder.requireLowercase(custom.isRequireLowercase());
        }

        if (custom.isRequireUppercase() != defaults.isRequireUppercase()) {
            builder.requireUppercase(custom.isRequireUppercase());
        }

        if (custom.isRequireNumbers() != defaults.isRequireNumbers()) {
            builder.requireNumbers(custom.isRequireNumbers());
        }

        if (custom.isRequireSpecialChars() != defaults.isRequireSpecialChars()) {
            builder.requireSpecialChars(custom.isRequireSpecialChars());
        }

        return builder.build();
    }

    private SessionSettings mergeSessionSettings(SessionSettings defaults, SessionSettings custom) {
        SessionSettings.SessionSettingsBuilder builder = SessionSettings.builder();

        // Set defaults
        builder.idleTimeout(defaults.getIdleTimeout());
        builder.absoluteTimeout(defaults.getAbsoluteTimeout());
        builder.persistentSessions(defaults.isPersistentSessions());

        // Override with custom values
        if (custom.getIdleTimeout() > 0) {
            builder.idleTimeout(custom.getIdleTimeout());
        }

        if (custom.getAbsoluteTimeout() > 0) {
            builder.absoluteTimeout(custom.getAbsoluteTimeout());
        }

        if (custom.isPersistentSessions() != defaults.isPersistentSessions()) {
            builder.persistentSessions(custom.isPersistentSessions());
        }

        return builder.build();
    }

    private SocialLoginSettings mergeSocialSettings(SocialLoginSettings defaults, SocialLoginSettings custom) {
        SocialLoginSettings.SocialLoginSettingsBuilder builder = SocialLoginSettings.builder();

        // Set defaults
        builder.enabled(defaults.isEnabled());
        builder.providers(defaults.getProviders());

        // Override with custom values
        if (custom.isEnabled() != defaults.isEnabled()) {
            builder.enabled(custom.isEnabled());
        }

        if (custom.getProviders() != null && !custom.getProviders().isEmpty()) {
            builder.providers(custom.getProviders());
        }

        return builder.build();
    }

    private EmailSettings mergeEmailSettings(EmailSettings defaults, EmailSettings custom) {
        EmailSettings.EmailSettingsBuilder builder = EmailSettings.builder();

        // Set defaults
        builder.verificationRequired(defaults.isVerificationRequired());
        builder.welcomeEmailEnabled(defaults.isWelcomeEmailEnabled());

        // Override with custom values
        if (custom.isVerificationRequired() != defaults.isVerificationRequired()) {
            builder.verificationRequired(custom.isVerificationRequired());
        }

        if (custom.isWelcomeEmailEnabled() != defaults.isWelcomeEmailEnabled()) {
            builder.welcomeEmailEnabled(custom.isWelcomeEmailEnabled());
        }

        return builder.build();
    }

    private BrandingSettings mergeBrandingSettings(BrandingSettings defaults, BrandingSettings custom) {
        BrandingSettings.BrandingSettingsBuilder builder = BrandingSettings.builder();

        // Start with defaults
        builder.logoUrl(defaults.getLogoUrl());
        builder.faviconUrl(defaults.getFaviconUrl());
        builder.colors(defaults.getColors());
        builder.fonts(defaults.getFonts());
        builder.customCss(defaults.getCustomCss());
        builder.loginPage(defaults.getLoginPage());

        // Override with custom values
        if (custom.getLogoUrl() != null && !custom.getLogoUrl().isEmpty()) {
            builder.logoUrl(custom.getLogoUrl());
        }

        if (custom.getFaviconUrl() != null && !custom.getFaviconUrl().isEmpty()) {
            builder.faviconUrl(custom.getFaviconUrl());
        }

        if (custom.getColors() != null) {
            builder.colors(mergeColorSettings(defaults.getColors(), custom.getColors()));
        }

        if (custom.getFonts() != null) {
            builder.fonts(mergeFontSettings(defaults.getFonts(), custom.getFonts()));
        }

        if (custom.getCustomCss() != null) {
            builder.customCss(mergeCustomCssSettings(defaults.getCustomCss(), custom.getCustomCss()));
        }

        if (custom.getLoginPage() != null) {
            builder.loginPage(mergeLoginPageSettings(defaults.getLoginPage(), custom.getLoginPage()));
        }

        return builder.build();
    }

    private ColorSettings mergeColorSettings(ColorSettings defaults, ColorSettings custom) {
        ColorSettings.ColorSettingsBuilder builder = ColorSettings.builder();

        // Start with defaults
        builder.primary(defaults.getPrimary());
        builder.secondary(defaults.getSecondary());
        builder.accent(defaults.getAccent());
        builder.background(defaults.getBackground());
        builder.text(defaults.getText());
        builder.buttonText(defaults.getButtonText());

        // Override with custom values
        if (custom.getPrimary() != null && !custom.getPrimary().isEmpty()) {
            builder.primary(custom.getPrimary());
        }

        if (custom.getSecondary() != null && !custom.getSecondary().isEmpty()) {
            builder.secondary(custom.getSecondary());
        }

        if (custom.getAccent() != null && !custom.getAccent().isEmpty()) {
            builder.accent(custom.getAccent());
        }

        if (custom.getBackground() != null && !custom.getBackground().isEmpty()) {
            builder.background(custom.getBackground());
        }

        if (custom.getText() != null && !custom.getText().isEmpty()) {
            builder.text(custom.getText());
        }

        if (custom.getButtonText() != null && !custom.getButtonText().isEmpty()) {
            builder.buttonText(custom.getButtonText());
        }

        return builder.build();
    }

    private FontSettings mergeFontSettings(FontSettings defaults, FontSettings custom) {
        FontSettings.FontSettingsBuilder builder = FontSettings.builder();

        // Start with defaults
        builder.primary(defaults.getPrimary());
        builder.headings(defaults.getHeadings());
        builder.baseSize(defaults.getBaseSize());

        // Override with custom values
        if (custom.getPrimary() != null && !custom.getPrimary().isEmpty()) {
            builder.primary(custom.getPrimary());
        }

        if (custom.getHeadings() != null && !custom.getHeadings().isEmpty()) {
            builder.headings(custom.getHeadings());
        }

        if (custom.getBaseSize() > 0) {
            builder.baseSize(custom.getBaseSize());
        }

        return builder.build();
    }

    private CustomCssSettings mergeCustomCssSettings(CustomCssSettings defaults, CustomCssSettings custom) {
        CustomCssSettings.CustomCssSettingsBuilder builder = CustomCssSettings.builder();

        // Start with defaults
        builder.enabled(defaults.isEnabled());
        builder.customCssCode(defaults.getCustomCssCode());

        // Override with custom values
        if (custom.isEnabled() != defaults.isEnabled()) {
            builder.enabled(custom.isEnabled());
        }

        if (custom.getCustomCssCode() != null && !custom.getCustomCssCode().isEmpty()) {
            builder.customCssCode(custom.getCustomCssCode());
        }

        return builder.build();
    }

    private LoginPageSettings mergeLoginPageSettings(LoginPageSettings defaults, LoginPageSettings custom) {
        LoginPageSettings.LoginPageSettingsBuilder builder = LoginPageSettings.builder();

        // Start with defaults
        builder.title(defaults.getTitle());
        builder.subtitle(defaults.getSubtitle());
        builder.backgroundImageUrl(defaults.getBackgroundImageUrl());
        builder.showSignupLink(defaults.isShowSignupLink());
        builder.showForgotPasswordLink(defaults.isShowForgotPasswordLink());
        builder.termsUrl(defaults.getTermsUrl());
        builder.privacyUrl(defaults.getPrivacyUrl());
        builder.showSocialButtons(defaults.isShowSocialButtons());
        builder.socialButtonsLayout(defaults.getSocialButtonsLayout());

        // Override with custom values
        if (custom.getTitle() != null && !custom.getTitle().isEmpty()) {
            builder.title(custom.getTitle());
        }

        if (custom.getSubtitle() != null && !custom.getSubtitle().isEmpty()) {
            builder.subtitle(custom.getSubtitle());
        }

        if (custom.getBackgroundImageUrl() != null && !custom.getBackgroundImageUrl().isEmpty()) {
            builder.backgroundImageUrl(custom.getBackgroundImageUrl());
        }

        if (custom.isShowSignupLink() != defaults.isShowSignupLink()) {
            builder.showSignupLink(custom.isShowSignupLink());
        }

        if (custom.isShowForgotPasswordLink() != defaults.isShowForgotPasswordLink()) {
            builder.showForgotPasswordLink(custom.isShowForgotPasswordLink());
        }

        if (custom.getTermsUrl() != null && !custom.getTermsUrl().isEmpty()) {
            builder.termsUrl(custom.getTermsUrl());
        }

        if (custom.getPrivacyUrl() != null && !custom.getPrivacyUrl().isEmpty()) {
            builder.privacyUrl(custom.getPrivacyUrl());
        }

        if (custom.isShowSocialButtons() != defaults.isShowSocialButtons()) {
            builder.showSocialButtons(custom.isShowSocialButtons());
        }

        if (custom.getSocialButtonsLayout() != null) {
            builder.socialButtonsLayout(custom.getSocialButtonsLayout());
        }

        return builder.build();
    }
}
