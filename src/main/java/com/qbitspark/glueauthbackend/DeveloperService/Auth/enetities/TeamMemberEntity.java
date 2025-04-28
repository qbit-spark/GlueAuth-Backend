package com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.InvitationStatus;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.TeamRole;
import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "team_members")
public class TeamMemberEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "team_id", nullable = false)
    private TeamEntity team;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private AccountEntity user;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private TeamRole role;

    @Column(name = "joined_at", nullable = false)
    private LocalDateTime joinedAt;

    @Column(name = "invitation_status")
    @Enumerated(EnumType.STRING)
    private InvitationStatus invitationStatus;
}



