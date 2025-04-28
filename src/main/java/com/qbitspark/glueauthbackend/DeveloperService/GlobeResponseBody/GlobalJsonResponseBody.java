package com.qbitspark.glueauthbackend.DeveloperService.GlobeResponseBody;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class GlobalJsonResponseBody {
    private Boolean success;
    private HttpStatus httpStatus;
    private String message;
    private LocalDateTime actionTime;
    private Object data;


}

