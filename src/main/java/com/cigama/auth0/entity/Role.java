package com.cigama.auth0.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {
    ADMIN("ROLE_ADMIN"),
    UNAUTHORIZED_USER("ROLE_UNAUTHORIZED_USER"),
    AUTHORIZED_USER("ROLE_AUTHORIZED_USER"),
    THIRD_PARTY_CLIENT("ROLE_THIRD_PARTY_CLIENT");

    private final String authority;
}
