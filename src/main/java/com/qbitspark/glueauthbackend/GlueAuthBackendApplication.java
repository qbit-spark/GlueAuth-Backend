package com.qbitspark.glueauthbackend;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enetities.AccountRoles;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.repos.RoleRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
public class GlueAuthBackendApplication implements CommandLineRunner {
    @Autowired
    private  RoleRepo accounRoleRepo;
    

    public static void main(String[] args) {
        SpringApplication.run(GlueAuthBackendApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        createRoleIfNotExists("ROLE_ADMIN");
        createRoleIfNotExists("ROLE_DEVELOPER");
        createRoleIfNotExists("ROLE_STAFF");
    }

    private void createRoleIfNotExists(String roleName) {
        AccountRoles existingRole = accounRoleRepo.findByRoleName(roleName).orElse(null);

        if (existingRole == null) {
            AccountRoles newRole = new AccountRoles();
            newRole.setRoleName(roleName);
            accounRoleRepo.save(newRole);
        }
    }
}
