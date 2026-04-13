package com.cigama.auth0.mapper;

import com.cigama.auth0.dto.JwtPayload;
import com.cigama.auth0.dto.cache.PendingUserData;
import com.cigama.auth0.dto.request.RegisterRequest;
import com.cigama.auth0.dto.response.SessionResponse;
import com.cigama.auth0.dto.response.UserProfileResponse;
import com.cigama.auth0.dto.userdetails.CustomUserDetails;
import com.cigama.auth0.entity.RefreshToken;
import com.cigama.auth0.entity.User;
import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserMapper {

    // --- Methods ---
    /**
     * Maps a User entity to a JwtPayload DTO.
     */
    @Mapping(target = "role", expression = "java(user.getRole().getAuthority())")
    @Mapping(target = "clientId", source = "clientId")
    @Mapping(target = "deviceId", ignore = true)
    JwtPayload toJwtPayload(User user, String clientId);

    /**
     * Maps a JwtPayload to CustomUserDetails for use in the stateless JWT filter.
     */
    @Mapping(target = "password", constant = "")
    @Mapping(target = "enabled", constant = "true")
    CustomUserDetails toCustomUserDetails(JwtPayload payload);

    /**
     * Direct mapping from User entity to CustomUserDetails for the login flow.
     */
    @Mapping(target = "role", expression = "java(user.getRole().getAuthority())")
    @Mapping(target = "enabled", source = "user.isAuthorized")
    @Mapping(target = "clientId", source = "clientId")
    CustomUserDetails toCustomUserDetails(User user, String clientId);

    /**
     * Maps a User entity to a UserProfileResponse DTO.
     */
    UserProfileResponse toUserProfileResponse(User user);

    /**
     * Maps a RefreshToken entity to a SessionResponse DTO.
     */
    @Mapping(target = "isCurrent", ignore = true)
    SessionResponse toSessionResponse(RefreshToken refreshToken);
}
