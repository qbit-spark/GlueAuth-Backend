package com.qbitspark.glueauthbackend.Oauth2Server.Users.controllers;

import com.qbitspark.glueauthbackend.GlobeResponseBody.GlobalJsonResponseBody;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.payloads.DirectoryUserRequest;
import com.qbitspark.glueauthbackend.Oauth2Server.Users.service.DirectoryUserService;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.UUID;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/directory-users")
public class DirectoryUserController {

    private final DirectoryUserService directoryUserService;

    // Create user
    @PostMapping("/create")
    public GlobalJsonResponseBody createUser(@RequestBody DirectoryUserRequest request) {
        return generateSuccessResponseBody("User created successfully", directoryUserService.save(request), HttpStatus.OK);
    }

    // Get all users
    @GetMapping("/all")
    public GlobalJsonResponseBody getAllUsers() {
        return generateSuccessResponseBody("All users retrieved successfully", directoryUserService.findAll(), HttpStatus.OK);
    }

    // Get user by ID
    @GetMapping("/{id}")
    public GlobalJsonResponseBody getUserById(@PathVariable UUID id) {
        return generateSuccessResponseBody("User retrieved successfully", directoryUserService.findById(id), HttpStatus.OK);
    }

    // Get users by directory ID
    @GetMapping("/directory/{directoryId}")
    public GlobalJsonResponseBody getUsersByDirectoryId(@PathVariable UUID directoryId) {
        return generateSuccessResponseBody("Users retrieved successfully", directoryUserService.findAllByDirectoryId(directoryId), HttpStatus.OK);
    }



    private GlobalJsonResponseBody generateSuccessResponseBody(String message, Object data, HttpStatus statusCode) {
        return new GlobalJsonResponseBody(
                true,
                statusCode,
                message,
                LocalDateTime.now(),
                data
        );
    }
}
