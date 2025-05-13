package com.qbitspark.glueauthbackend.Oauth2Server.Clients.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.utils.StringSetConverter;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.enums.ApplicationType;
import com.qbitspark.glueauthbackend.Oauth2Server.enums.*;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "client_apps")
public class ClientAppEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(name = "client_id", unique = true, nullable = false)
    private String clientId;

    @Column(name = "client_name", nullable = false)
    private String clientName;

    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "application_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private ApplicationType applicationType;

    // Client type - missing in your entity
    @Column(name = "client_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private ClientsTypes clientType;

//    @ElementCollection
//    @CollectionTable(
//            name = "oauth_client_grant_types",
//            joinColumns = @JoinColumn(name = "client_id")
//    )
//    @Enumerated(EnumType.STRING)
//    @Column(name = "grant_type", nullable = false)
//    private Set<GrantType> authorizationGrantTypes = new HashSet<>();
//
//    @ElementCollection
//    @CollectionTable(
//            name = "oauth_client_auth_methods",
//            joinColumns = @JoinColumn(name = "client_id")
//    )
//    @Enumerated(EnumType.STRING)
//    @Column(name = "auth_method", nullable = false)
//    private Set<AuthenticationMethod> authenticationMethods = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)  // Add EAGER here
    @CollectionTable(
            name = "oauth_client_grant_types",
            joinColumns = @JoinColumn(name = "client_id")
    )
    @Enumerated(EnumType.STRING)
    @Column(name = "grant_type", nullable = false)
    private Set<GrantType> authorizationGrantTypes = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)  // Add EAGER here
    @CollectionTable(
            name = "oauth_client_auth_methods",
            joinColumns = @JoinColumn(name = "client_id")
    )
    @Enumerated(EnumType.STRING)
    @Column(name = "auth_method", nullable = false)
    private Set<AuthenticationMethod> authenticationMethods = new HashSet<>();


    @Column(name = "redirect_uris", columnDefinition = "jsonb")
    @Convert(converter = StringSetConverter.class)
    private Set<String> redirectUris = new HashSet<>();

    @Column(name = "use_refresh_tokens", nullable = false)
    private Boolean useRefreshTokens = false;

    // Token type - missing in your entity
    @Column(name = "token_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private TokenType tokenType;

    // PKCE requirement - missing in your entity
    @Column(name = "require_proof_key", nullable = false)
    private Boolean requireProofKey = false;

    @ManyToOne
    @JoinColumn(name = "directory_id", nullable = false)
    @JsonIgnoreProperties({"name", "description", "isActive", "settings",
            "clientApps", "users", "createdAt", "updatedAt", "owner",
            "hibernateLazyInitializer", "handler"})
    private DirectoryEntity directory;

    @JsonIgnoreProperties({"email", "passwordHash", "emailVerified", "accountName",
            "accountType", "organizationName", "organizationSize", "profilePictureUrl",
            "phoneNumber", "phoneVerified", "twoFactorEnabled", "socialAuthProvider",
            "socialLoginId", "lastLogin", "createdAt", "updatedAt", "subscriptionTier",
            "subscriptionStatus", "active", "locked", "lockedReason", "roles","socialLoginProvider",
            "teamMemberships", "ownedTeams", "hibernateLazyInitializer", "handler"})
    @ManyToOne
    @JoinColumn(name = "owner_id", nullable = false)
    private AccountEntity owner;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;
}