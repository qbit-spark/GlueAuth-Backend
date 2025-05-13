package com.qbitspark.glueauthbackend.Oauth2Server.Clients.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.UseDetails.CustomClientUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

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
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))

                .securityMatcher("/oauth2/**", "/.well-known/**", "/login", "/custom-login")
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(endpointsMatcher)
                        .ignoringRequestMatchers("/login")
                        .ignoringRequestMatchers("/.well-known/**")
                )
                .with(authorizationServerConfigurer, (authorizationServer) -> {
                    // Enable OpenID Connect with client-based directory context
                    authorizationServer.oidc(Customizer.withDefaults());
                })
                .authorizeHttpRequests((authorize) ->
                        authorize
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
                        // Optional: Custom access denied handler (for 403 Forbidden)
                        .accessDeniedPage("/access-denied")
                )
                .formLogin(form -> form
                        .loginPage("/custom-login")
                        .loginProcessingUrl("/login")
                        //.defaultSuccessUrl("/home", true)
                        .permitAll()
                )

                .userDetailsService(customClientUserDetailsService);


        return http.build();
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
        // Explicitly set the issuer URL to use port 9000
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8083")
                .build();
    }

}