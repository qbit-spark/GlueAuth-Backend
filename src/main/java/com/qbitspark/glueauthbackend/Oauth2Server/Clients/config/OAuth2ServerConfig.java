package com.qbitspark.glueauthbackend.Oauth2Server.Clients.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.UseDetails.CustomClientUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class OAuth2ServerConfig {
    private static final Logger logger = LoggerFactory.getLogger(OAuth2ServerConfig.class);

    @Value("${app.security.rsa.public-key}")
    private String publicKeyString;

    @Value("${app.security.rsa.private-key}")
    private String privateKeyString;

    @Qualifier("oauth2UserDetailsService")
    private final CustomClientUserDetailsService customClientUserDetailsService;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .invalidSessionUrl("/custom-login?expired")
                )

                .securityMatcher("/oauth2/**", "/.well-known/**", "/login", "/custom-login")
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(endpointsMatcher)
                        .ignoringRequestMatchers("/login")
                        .ignoringRequestMatchers("/.well-known/**")
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                )
                .with(authorizationServerConfigurer, (authorizationServer) -> {
                    // Enable OpenID Connect with client-based directory context
                    authorizationServer.oidc(Customizer.withDefaults());
                })
                .headers(headers -> headers
                        .xssProtection(xss -> xss
                                .headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';"))
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                )
                .authorizeHttpRequests((authorize) ->
                        authorize
                                .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()
                                .requestMatchers("/custom-login", "/error", "/login", "/.well-known/**").permitAll()
                                .anyRequest().authenticated()
                )
                .exceptionHandling((exceptions) -> exceptions
                        // For HTML browser requests - redirect to login
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/custom-login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                        // For API requests - return 401 with WWW-Authenticate header
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                new MediaTypeRequestMatcher(MediaType.APPLICATION_JSON)
                        )
                        // For AJAX requests
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest")
                        )
                        // Optional: Custom access denied handler (for 403 Forbidden)
                        .accessDeniedPage("/access-denied")
                )
                .formLogin(form -> form
                        .loginPage("/custom-login")
                        .loginProcessingUrl("/login")
                        .successHandler(customAuthenticationSuccessHandler())
                        .failureHandler(customAuthenticationFailureHandler())
                        .permitAll()
                )
                .userDetailsService(customClientUserDetailsService);

        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler customAuthenticationSuccessHandler() {
        return (request, response, authentication) -> {
            // Audit logging
            logger.info("User {} successfully authenticated from IP {}",
                    authentication.getName(),
                    request.getRemoteAddr());

            // Client ID handling for OAuth flows
            String clientId = (String) request.getSession().getAttribute("CLIENT_ID");

            // Get the originally requested URL
            SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);

            // Determine redirect URL
            String redirectUrl;

            if (savedRequest != null && savedRequest.getRedirectUrl().contains("/oauth2/authorize")) {
                // For OAuth flows, redirect back to the authorization endpoint
                redirectUrl = savedRequest.getRedirectUrl();
            } else if (clientId != null) {
                // If there's a client ID but no saved request, recreate authorization request
                redirectUrl = "/oauth2/authorize?client_id=" + clientId + "&response_type=code";
            } else {
                // Default redirect
                redirectUrl = "/home";
            }

            // Clear sensitive session attributes
            request.getSession().removeAttribute("SPRING_SECURITY_SAVED_REQUEST");

            response.sendRedirect(redirectUrl);
        };
    }

    @Bean
    public AuthenticationFailureHandler customAuthenticationFailureHandler() {
        return (request, response, exception) -> {
            // Security logging
            logger.warn("Authentication failure for username: {}, reason: {}, IP: {}",
                    request.getParameter("username"),
                    exception.getMessage(),
                    request.getRemoteAddr());

            // Preserve client_id between requests
            String clientId = request.getParameter("client_id");
            if (clientId == null) {
                clientId = (String) request.getSession().getAttribute("CLIENT_ID");
            }

            // Build error URL
            String redirectUrl = "/custom-login?error";
            if (clientId != null) {
                redirectUrl += "&client_id=" + clientId;
            }

            // Add specific error codes for better UX
            if (exception instanceof BadCredentialsException) {
                redirectUrl += "&code=invalid_credentials";
            } else if (exception instanceof LockedException) {
                redirectUrl += "&code=account_locked";
            } else if (exception instanceof DisabledException) {
                redirectUrl += "&code=account_disabled";
            }

            response.sendRedirect(redirectUrl);
        };
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // Generate a fixed key ID
        String keyId = "auth-server-kid";

        // Load RSA keys from properties
        KeyPair keyPair = loadRsaKeys();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private KeyPair loadRsaKeys() {
        try {
            // Convert Base64 encoded strings to byte arrays
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);

            // Get RSA key factory
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            // Create public key
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

            // Create private key
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

            // Return key pair
            return new KeyPair(publicKey, privateKey);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load RSA keys", ex);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        // Set the issuer URL
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8083")
                .build();
    }
}