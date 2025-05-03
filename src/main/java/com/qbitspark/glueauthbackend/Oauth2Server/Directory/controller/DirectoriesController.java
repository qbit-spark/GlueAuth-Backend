package com.qbitspark.glueauthbackend.Oauth2Server.Directory.controller;

import com.qbitspark.glueauthbackend.GlobeResponseBody.GlobalJsonResponseBody;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.Entities.DirectoryEntity;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.payloads.CreateDirectoryRequest;
import com.qbitspark.glueauthbackend.Oauth2Server.Directory.services.DirectoriesService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/directories")
public class DirectoriesController {

    private final DirectoriesService directoriesService;

    @PostMapping("/create")
    public ResponseEntity<GlobalJsonResponseBody> createDirectory(@RequestBody CreateDirectoryRequest request) {
       directoriesService.createDirectory(request);
        return ResponseEntity.ok(generateSuccessResponseBody("Directory created successfully", null, HttpStatus.OK));
    }

    @GetMapping("/all")
    public ResponseEntity<GlobalJsonResponseBody> getAllDirectories() {
        return ResponseEntity.ok(generateSuccessResponseBody("All directories retrieved successfully", directoriesService.getAllDirectories(), HttpStatus.OK));
    }

    @GetMapping("/mine-all")
    public ResponseEntity<GlobalJsonResponseBody> getAllDirectoriesByAccount() {
        return ResponseEntity.ok(generateSuccessResponseBody("All directories retrieved successfully", directoriesService.getDirectoriesByLoginAccount(), HttpStatus.OK));
    }

    @GetMapping("/{id}")
    public ResponseEntity<GlobalJsonResponseBody> getDirectoryById(@PathVariable UUID id) {
        return ResponseEntity.ok(generateSuccessResponseBody("Directory retrieved successfully", directoriesService.getDirectoryByIdAndAccount(id), HttpStatus.OK));
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


