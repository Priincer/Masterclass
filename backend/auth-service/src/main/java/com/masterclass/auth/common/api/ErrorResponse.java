package com.masterclass.auth.common.api;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class ErrorResponse {
    String timestamp;
    int status;
    String error;
    String code;
    String message;
    String path;
}