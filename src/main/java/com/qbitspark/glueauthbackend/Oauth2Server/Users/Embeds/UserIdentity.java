package com.qbitspark.glueauthbackend.Oauth2Server.Users.Embeds;


import com.qbitspark.glueauthbackend.Oauth2Server.Users.Enum.IdentityType;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.Enum.Provider;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Embeddable
@Data
@NoArgsConstructor
public class UserIdentity {

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private IdentityType type;

    @Enumerated(EnumType.STRING)
    private Provider provider;

    private String providerUserId;

    private String token;

    private LocalDateTime tokenExpiresAt;

    @Column(columnDefinition = "jsonb")
    private String profileData;

    private LocalDateTime lastUsedAt;

    private boolean verified = false;

}