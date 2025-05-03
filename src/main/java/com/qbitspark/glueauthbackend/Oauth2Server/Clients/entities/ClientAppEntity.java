package com.qbitspark.glueauthbackend.Oauth2Server.Clients.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.UserEntity;
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
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "client_apps")
public class ClientAppEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String name;

    @Column(length = 1000)
    private String description;

    @Column(nullable = false, unique = true)
    private String clientId;

    @Column(columnDefinition = "TEXT")
    private String clientSecret;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private ApplicationType applicationType;

    @Column(nullable = false)
    private Boolean isActive = true;


    @Column(columnDefinition = "jsonb")
    private String redirectUris;


    @ElementCollection
    @CollectionTable(
            name = "client_grant_types",
            joinColumns = @JoinColumn(name = "client_app_id")
    )
    @Enumerated(EnumType.STRING)
    private Set<GrantType> allowedGrantTypes = new HashSet<>();


    @Enumerated(EnumType.STRING)
    private TokenFormat accessTokenFormat ;

    @Enumerated(EnumType.STRING)
    private TokenFormat refreshTokenFormat;


    private String tokenSigningAlgorithm = "RS256";


    @Column(columnDefinition = "jsonb")
    private String settings;


    private Boolean hasCustomSettings = false;


    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "directory_id", nullable = false)
    private DirectoryEntity directory;


    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "client_app_users",
            joinColumns = @JoinColumn(name = "client_app_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id")
    )
    private Set<UserEntity> assignedUsers = new HashSet<>();


    private Integer accessTokenLifetime = 3600;  // 1 hour in seconds
    private Integer refreshTokenLifetime = 2592000;  // 30 days in seconds
    private Integer idTokenLifetime = 3600; // 1 hour in seconds


    private Boolean pkceRequired = false;
    private Boolean consentRequired = false;
    private Boolean rotateRefreshToken = true;


    private Integer authCodeLifetime = 60; // 1 minute in seconds
    private Integer deviceCodeLifetime = 600; // 10 minutes in seconds


    @Column(columnDefinition = "jsonb")
    private String allowedCorsOrigins;


    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    @Column(length = 100)
    private String createdBy;

    @Column(length = 100)
    private String updatedBy;


    private Long totalLogins = 0L;
    private LocalDateTime lastAccessedAt;

}