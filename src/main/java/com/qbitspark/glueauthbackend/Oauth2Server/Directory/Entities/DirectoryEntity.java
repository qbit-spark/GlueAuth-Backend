package com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.entities.ClientAppEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.DirectoryUserEntity;
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
@Table(name = "directories")
public class DirectoryEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String name;

    @Column(length = 1000)
    private String description;

    @Column(nullable = false)
    private Boolean isActive = true;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "account_id", nullable = false)
    @JsonIgnoreProperties({"email", "passwordHash", "emailVerified", "accountName",
            "accountType", "organizationName", "organizationSize", "profilePictureUrl",
            "phoneNumber", "phoneVerified", "twoFactorEnabled", "socialAuthProvider",
            "socialLoginId", "lastLogin", "createdAt", "updatedAt", "subscriptionTier",
            "subscriptionStatus", "active", "locked", "lockedReason", "roles","socialLoginProvider",
            "teamMemberships", "ownedTeams", "hibernateLazyInitializer", "handler"})
    private AccountEntity owner;

    @Column(columnDefinition = "jsonb")
    private String settings;


    @OneToMany(mappedBy = "directory", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<ClientAppEntity> clientApps = new ArrayList<>();

    @JsonIgnore
    @OneToMany(mappedBy = "directory", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<DirectoryUserEntity> users = new ArrayList<>();

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    @Column(length = 100)
    private String createdBy;

    @Column(length = 100)
    private String updatedBy;
}