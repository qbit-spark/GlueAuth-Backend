package com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.AccountType;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.OrganizationSize;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.SubscriptionStatus;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.SubscriptionTier;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@RequiredArgsConstructor
@Getter
@Setter
@Table(name = "developer_account")
public class AccountEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(name = "username", unique = true, nullable = false)
    private String username;

    @JsonIgnore
    @Column(name = "password_hash")
    private String passwordHash;

    @Column(name = "email_verified")
    private boolean emailVerified;

    @Column(name = "account_name")
    private String accountName;

    @Enumerated(EnumType.STRING)
    @Column(name = "account_type")
    private AccountType accountType;

    @Column(name = "organization_name")
    private String organizationName;

    @Column(name = "organization_size")
    private OrganizationSize organizationSize;

    @Column(name = "profile_picture_url")
    private String profilePictureUrl;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "phone_verified")
    private boolean phoneVerified;

    @Column(name = "two_factor_enabled")
    private boolean twoFactorEnabled;

    @Column(name = "social_login_provider")
    private String socialLoginProvider;

    @Column(name = "social_login_id")
    private String socialLoginId;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "subscription_tier")
    private SubscriptionTier subscriptionTier;

    @Column(name = "subscription_status")
    private SubscriptionStatus subscriptionStatus;

    @Column(name = "active")
    private boolean active;

    @Column(name = "locked")
    private boolean locked;

    @Column(name = "locked_reason")
    private String lockedReason;

    @JsonIgnore
    @ManyToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinTable(name = "developer_account_roles",
            joinColumns = @JoinColumn(name = "account_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "role_id"))
    private Set<AccountRoles> roles;

    @JsonIgnore
    @JsonManagedReference
    // Reverse relationship to handle teams that a user belongs to
    @OneToMany(mappedBy = "user")
    private Set<TeamMemberEntity> teamMemberships = new HashSet<>();

    @JsonIgnore
    // For organization accounts, their owned teams
    @OneToMany(mappedBy = "account")
    private Set<TeamEntity> ownedTeams = new HashSet<>();

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}