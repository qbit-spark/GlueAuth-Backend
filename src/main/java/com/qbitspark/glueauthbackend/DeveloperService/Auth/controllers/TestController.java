package com.qbitspark.glueauthbackend.DeveloperService.Auth.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {
    // Test endpoint
    @GetMapping("/hello-private")
    public String hello() {
        return "Hello, Private world!";
    }

    // Add public methods for testing purposes
    @GetMapping("/hello-public")
    public String helloPublic() {
        return "Hello, Public World!";
    }
}
