package com.qbitspark.glueauthbackend.Oauth2Server.Clients.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.jwt.DirectoryAwareJwtCustomizer;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.jwt.DirectoryAwareOidcUserInfoService;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.jwt.DirectoryContextFilter;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.service.IMPL.DirectoryAwareUserDetailsService;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.utils.DirectoryContextHolder;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class OAuth2ServerConfig {

    @Qualifier("directoryAwareUserDetailsService")
    private final DirectoryAwareUserDetailsService userDetailsService;
    private final DirectoryAwareJwtCustomizer jwtCustomizer;
    private final DirectoryAwareOidcUserInfoService oidcUserInfoService;
    private final DirectoryContextFilter directoryContextFilter;

    @Value("${app.security.rsa.public-key}")
    private String publicKeyString;

    @Value("${app.security.rsa.private-key}")
    private String privateKeyString;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        // Add directory context filter before authentication
        http.addFilterBefore(directoryContextFilter, UsernamePasswordAuthenticationFilter.class);

        http
                // ONLY use the OAuth2 server endpoints matcher to prevent conflicts
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher())
                )
                .with(authorizationServerConfigurer, (authorizationServer) -> {
                    // Enable the consent page with directory context
                    authorizationServer.authorizationEndpoint(authorizationEndpoint ->
                            authorizationEndpoint.consentPage("/oauth2/consent"));

                    // Add token customizer to include directory claims
                    authorizationServer.tokenGenerator(tokenGenerator(jwkSource()));

                    // Enable OpenID Connect with directory-aware user info
                    authorizationServer.oidc(oidc ->
                            oidc.userInfoEndpoint(userInfo ->
                                    userInfo.userInfoMapper(context -> {
                                        // Extract authentication from context
                                        Authentication authentication = context.getAuthentication();

                                        // Create user info with directory context
                                        UUID directoryId = DirectoryContextHolder.getDirectoryId();
                                        if (directoryId != null) {
                                            // Find user in directory context
                                            String username = authentication.getName();
                                            return oidcUserInfoService.createUserInfo(username, directoryId);
                                        }

                                        return null;
                                    })));
                })
                .authorizeHttpRequests((authorize) ->
                        authorize
                                .requestMatchers("/oauth2/consent").permitAll()
                                .anyRequest().authenticated()
                )
                .exceptionHandling((exceptions) -> exceptions
                        // For HTML browser requests - redirect to login with directory context
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/auth/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                        // For API requests - return 401 with WWW-Authenticate header
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                new MediaTypeRequestMatcher(MediaType.APPLICATION_JSON)
                        )
                        // Custom access denied handler (for 403 Forbidden)
                        .accessDeniedPage("/access-denied")
                )
                // Set directory-aware user details service
                .userDetailsService(userDetailsService);

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // Add directory context filter before authentication
        http.addFilterBefore(directoryContextFilter, UsernamePasswordAuthenticationFilter.class);

        http
                // Define specific URL patterns this chain will handle
                .securityMatcher("/auth/**", "/api/v1/account/**", "/assets/**", "/webjars/**")
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/api/v1/account/**").permitAll()
                        .requestMatchers("/auth/login", "/auth/register", "/auth/error").permitAll()
                        .requestMatchers("/assets/**", "/webjars/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(login -> login
                        .loginPage("/auth/login")
                        .loginProcessingUrl("/auth/login-process")
                        .failureUrl("/auth/error")
                );

        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // Generate a fixed key ID
        String keyId = "glueauth-server-kid";

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

            // Create a public key
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

            // Create a private key
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

            // Return a key pair
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
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return jwtCustomizer;
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("https://auth.glueauth.com")
                .build();
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
        // Create JWT encoder
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);

        // Create JWT generator
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);

        // Set your customizer on the JWT generator
        jwtGenerator.setJwtCustomizer(jwtCustomizer);

        // Create standard token generators
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        // Return combined generator
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator,
                accessTokenGenerator,
                refreshTokenGenerator
        );
    }
}