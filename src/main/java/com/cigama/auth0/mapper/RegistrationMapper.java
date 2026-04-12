package com.cigama.auth0.mapper;

import com.cigama.auth0.dto.cache.PendingUserData;
import com.cigama.auth0.dto.request.RegisterRequest;
import com.cigama.auth0.entity.User;
import com.cigama.auth0.event.dto.PendingRegistrationEvent;
import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

/**
 * Mapper dedicated to the registration pipeline:
 * RegisterRequest -> PendingUserData (Redis)
 * RegisterRequest -> PendingRegistrationEvent (Stream)
 * PendingUserData -> User Entity (PostgreSQL)
 */
@Mapper(componentModel = "spring")
public interface RegistrationMapper {

    /**
     * Maps the incoming registration request and security metadata (encoded password, OTP)
     * to a transient DTO for Redis caching.
     */
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "email", source = "request.email")
    @Mapping(target = "phoneNumber", source = "request.phoneNumber")
    @Mapping(target = "firstName", source = "request.firstName")
    @Mapping(target = "lastName", source = "request.lastName")
    @Mapping(target = "username", source = "request.username")
    @Mapping(target = "dateOfBirth", source = "request.dateOfBirth")
    @Mapping(target = "password", source = "encodedPassword")
    @Mapping(target = "otpCode", source = "otpCode")
    @Mapping(target = "clientId", source = "clientId")
    PendingUserData toPendingUserData(RegisterRequest request, String encodedPassword, String otpCode, String clientId);

    /**
     * Maps the registration request and metadata to an event for Redis Stream processing.
     * This decouples the service from event structure details.
     */
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "email", source = "request.email")
    @Mapping(target = "username", source = "request.username")
    @Mapping(target = "registrationId", source = "registrationId")
    @Mapping(target = "otpCode", source = "otpCode")
    PendingRegistrationEvent toRegistrationEvent(RegisterRequest request, String registrationId, String otpCode);

    /**
     * Converts the cached pending user data back to a persistent User entity
     * once the OTP verification is successful.
     */
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "email", source = "email")
    @Mapping(target = "phoneNumber", source = "phoneNumber")
    @Mapping(target = "password", source = "password")
    @Mapping(target = "firstName", source = "firstName")
    @Mapping(target = "lastName", source = "lastName")
    @Mapping(target = "username", source = "username")
    @Mapping(target = "dateOfBirth", source = "dateOfBirth")
    User pendingToUser(PendingUserData pendingData);
}
