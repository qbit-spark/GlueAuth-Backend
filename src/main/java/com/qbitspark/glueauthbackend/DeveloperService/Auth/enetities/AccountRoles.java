package com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Entity

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Table(name = "roles_table")
public class AccountRoles {
    @JsonIgnore
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "role_id")
    private UUID roleId;

    @Column(name = "role_name")
    private String roleName;
}