package com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities;

import com.qbitspark.glueauthbackend.Oauth2Server.Clients.Entities.ClientAppEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Entities.UserEntity;
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

    @Column(columnDefinition = "jsonb")
    private String settings;

    @OneToMany(mappedBy = "directory", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Set<ClientAppEntity> clientApps = new HashSet<>();


    @OneToMany(mappedBy = "directory", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Set<UserEntity> users = new HashSet<>();

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    @Column(length = 100)
    private String createdBy;

    @Column(length = 100)
    private String updatedBy;
}