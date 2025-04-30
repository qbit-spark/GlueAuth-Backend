package com.qbitspark.glueauthbackend.DeveloperService.Auth.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {
    // Test endpoint
    @GetMapping("/hello")
    public String hello() {
        return "Hello, World!";
    }

    // Add more test endpoints as needed
}
