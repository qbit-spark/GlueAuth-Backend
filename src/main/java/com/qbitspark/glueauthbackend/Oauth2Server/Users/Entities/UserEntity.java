package com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities;

import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;

import com.qbitspark.glueauthbackend.Oauth2Server.Users.Embeds.UserIdentity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Enum.IdentityType;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Enum.Provider;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "directory_users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true)
    private String username;

    @Column(unique = true)
    private String email;

    @Column(unique = true)
    private String phoneNumber;

    private String password;


    @Column(nullable = false)
    private boolean enabled = true;

    @Column(nullable = false)
    private boolean requiredVerification = false;


    @ElementCollection
    @CollectionTable(
            name = "user_identities",
            joinColumns = @JoinColumn(name = "user_id")
    )
    private Set<UserIdentity> identities = new HashSet<>();


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "directory_id")
    private DirectoryEntity directory;


    @Column(columnDefinition = "jsonb")
    private String metadata;


    private LocalDateTime lastLoginAt;
    private Integer loginCount = 0;


    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;


}