package com.qbitspark.glueauthbackend.Oauth2Server.Clients.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.DirectoryUserEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Enum.ApplicationType;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Enum.GrantType;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Enum.TokenFormat;
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

    @Column(name = "client_secret", nullable = false)
    private String clientSecret;

    @Column(name = "authorization_grant_type", nullable = false)
    private String authorizationGrantType;

    @Column(name = "redirect_uri", nullable = false)
    private String redirectUri;

    @Column(name = "require_proof_key", nullable = false)
    private boolean requireProofKey;

    @Column(name = "token_format", nullable = false)
    private String tokenFormat;


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

}