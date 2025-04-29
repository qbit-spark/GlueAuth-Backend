package com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads;

import lombok.Data;

@Data
public class GithubUserInfo {
    private String id;
    private String email;
    private String name;
    private String avatarUrl;
}
