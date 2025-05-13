package com.qbitspark.glueauthbackend.Oauth2Server.Clients.controller;

import com.qbitspark.glueauthbackend.GlobeResponseBody.GlobalJsonResponseBody;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.payload.RegisterClientRequest;
import com.qbitspark.glueauthbackend.Oauth2Server.Clients.service.ClientAppService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/clients")
public class ClientAppController {

    private final ClientAppService clientAppService;

    @PostMapping("/create")
    public ResponseEntity<GlobalJsonResponseBody> createClientApp(@Validated @RequestBody RegisterClientRequest request) {
        return ResponseEntity.ok(generateSuccessResponseBody("Client App created successfully", clientAppService.createClientApp(request), HttpStatus.OK));
    }


    @GetMapping("/all")
    public ResponseEntity<GlobalJsonResponseBody> getAllClientApps() {
        return ResponseEntity.ok(generateSuccessResponseBody("Client Apps retrieved successfully", clientAppService.getAllClientApps(), HttpStatus.OK));
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
