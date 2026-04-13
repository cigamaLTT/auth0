package com.cigama.auth0.dto.response;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record BaseResponse<T>(
    Integer status,
    String message,
    T data
) {}
