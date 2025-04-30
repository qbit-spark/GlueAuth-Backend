package com.qbitspark.glueauthbackend.DeveloperService.GlobeSecurity.Configuration;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.Auth2Handler.OAuth2AuthenticationSuccessHandler;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.utils.CookieUtils;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeSecurity.CustomAuthenticationEntryPoint;
import com.qbitspark.glueauthbackend.DeveloperService.GlobeSecurity.JWTAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@RequiredArgsConstructor
@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {

    @Autowired
    @Qualifier("handlerExceptionResolver")
    private HandlerExceptionResolver exceptionResolver;

    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Value("${app.frontend.baseUrl}")
    private String frontendBaseUrl;

    @Value("${app.cors.allowed-origins}")
    private String allowedOrigins;

    @Value("${app.cors.allowed-methods}")
    private String allowedMethods;

    @Value("${app.cors.allowed-headers}")
    private String allowedHeaders;

    @Value("${app.cors.allow-credentials}")
    private boolean allowCredentials;

    @Bean
    public JWTAuthFilter jwtAuthenticationFilter() {
        return new JWTAuthFilter(exceptionResolver);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        configuration.setAllowedMethods(Arrays.asList(allowedMethods.split(",")));
        configuration.setAllowedHeaders(Arrays.asList(allowedHeaders.split(",")));
        configuration.setAllowCredentials(allowCredentials);
        configuration.setExposedHeaders(Arrays.asList("Set-Cookie"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        // Set the name of the attribute the CsrfToken will be populated on
        requestHandler.setCsrfRequestAttributeName("_csrf");

        httpSecurity
                // Configure CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // Enable CSRF protection with cookies
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(requestHandler)
                        // Disable CSRF for these specific paths that need to be accessible for OAuth and initial auth
                        .ignoringRequestMatchers(
                                new AntPathRequestMatcher("/api/v1/account", HttpMethod.POST.toString()),
                                new AntPathRequestMatcher("/api/v1/account/login", HttpMethod.POST.toString()),
                                new AntPathRequestMatcher("/api/v1/account/logout", HttpMethod.POST.toString()),
                                new AntPathRequestMatcher("/api/v1/account/refresh", HttpMethod.POST.toString()),
                                new AntPathRequestMatcher("/api/account/oauth2/callback/*")
                        )
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, "/api/v1/account/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/account/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/test/**").permitAll() // Allow test endpoints
                        .requestMatchers(HttpMethod.GET, "/images/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .redirectionEndpoint(endpoint -> endpoint
                                .baseUri("/api/account/oauth2/callback/*"))
                        .successHandler(oAuth2AuthenticationSuccessHandler))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(customAuthenticationEntryPoint))
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        httpSecurity.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }
}