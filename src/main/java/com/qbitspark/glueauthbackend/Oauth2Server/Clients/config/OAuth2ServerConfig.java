package com.qbitspark.glueauthbackend.Oauth2Server.Clients.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.UseDetails.CustomClientUserDetailsService;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.service.IMPL.ClientAppServiceIMPL;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.NoneAuthenticator.DeviceClientAuthenticationConverter;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.config.NoneAuthenticator.DeviceClientAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
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

    // Autowire ClientAppServiceIMPL directly since it implements RegisteredClientRepository
    private final ClientAppServiceIMPL clientAppService;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                                      AuthorizationServerSettings authorizationServerSettings)
            throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        // Create device client authentication components using clientAppService as the repository
        DeviceClientAuthenticationConverter deviceClientAuthenticationConverter = new DeviceClientAuthenticationConverter(authorizationServerSettings.getDeviceAuthorizationEndpoint());
        DeviceClientAuthenticationProvider deviceClientAuthenticationProvider = new DeviceClientAuthenticationProvider(clientAppService);

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();


        http
                .securityMatcher("/oauth2/**", "/.well-known/**", "/login")
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(endpointsMatcher)
                )

                .with(authorizationServerConfigurer, (authorizationServer) -> {
                    authorizationServer
                            .deviceAuthorizationEndpoint(deviceAuthEndpoint ->
                                    deviceAuthEndpoint.verificationUri("/oauth2/device_verification"))


                            // Add client authentication configuration for device flow
                            .clientAuthentication(clientAuth ->
                                    clientAuth
                                            .authenticationConverter(deviceClientAuthenticationConverter)
                                            .authenticationProvider(deviceClientAuthenticationProvider)
                            )
                            .oidc(Customizer.withDefaults());
                })
                .authorizeHttpRequests((authorize) ->
                        authorize
                                .requestMatchers("/oauth2/device_authorization").permitAll()
                                .anyRequest().authenticated()
                )

                .formLogin(Customizer.withDefaults())
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
        // Set the issuer URL
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8083")
                .deviceAuthorizationEndpoint("/oauth2/device_authorization")
                .build();
    }

    // This bean creates the database-backed implementation of OAuth2AuthorizationService
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
                                                           RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    // This bean creates the consent service
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
                                                                         RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }


}