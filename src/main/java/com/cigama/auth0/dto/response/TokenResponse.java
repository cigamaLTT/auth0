package com.cigama.auth0.dto.response;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class TokenResponse {

    private String accessToken;

    private String tokenType;

    private Long expiredIn;

}
