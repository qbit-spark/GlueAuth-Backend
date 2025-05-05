package com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities;

import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Embeds.UserIdentity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.*;

@Entity
@Table(
        name = "directory_users"
)
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DirectoryUserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;


    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String email;

    private String phoneNumber;

    // Authentication credentials
    @Column(nullable = false)
    private String password;

    // Basic profile info
    private String firstName;
    private String lastName;
    private String displayName;
    private String profilePictureUrl;

    // Account status flags
    @Column(nullable = false)
    private boolean enabled = true;

    @Column(nullable = false)
    private boolean emailVerified = false;

    private boolean phoneVerified = false;
    private boolean twoFactorEnabled = false;

    // Security and account state
    private int failedLoginAttempts = 0;
    private LocalDateTime lockedUntil;
    private boolean accountExpired = false;
    private boolean credentialsExpired = false;
    private boolean locked = false;

    // Critical association with directory (enforces isolation)
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "directory_id", nullable = false)
    private DirectoryEntity directory;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "directory_user_permissions",
            joinColumns = @JoinColumn(name = "user_id")
    )
    @Column(name = "permission")
    private List<String> permissions = new ArrayList<>();


    // External identity providers (social logins)
    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(
            name = "user_identities",
            joinColumns = @JoinColumn(name = "user_id")
    )
    private List<UserIdentity> identities = new ArrayList<>();

    // Custom user attributes (extensible schema)
    @Column(columnDefinition = "jsonb")
    private String metadata;

    // Audit and analytics data
    private LocalDateTime lastLoginAt;
    private Integer loginCount = 0;
    private LocalDateTime passwordLastChanged;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    private String createdBy;
    private String updatedBy;


    // Helper methods for account management
    public boolean isAccountNonExpired() {
        return !accountExpired;
    }

    public boolean isAccountNonLocked() {
        return !locked && (lockedUntil == null || lockedUntil.isBefore(LocalDateTime.now()));
    }

    public boolean isCredentialsNonExpired() {
        return !credentialsExpired;
    }

    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts++;
    }

    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
    }

    public void recordSuccessfulLogin() {
        this.lastLoginAt = LocalDateTime.now();
        this.loginCount = (this.loginCount != null ? this.loginCount : 0) + 1;
        this.resetFailedLoginAttempts();
    }
}