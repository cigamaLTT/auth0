package com.cigama.auth0.mapper;

import com.cigama.auth0.dto.request.ForgotPasswordRequest;
import com.cigama.auth0.event.dto.ForgotPasswordEvent;
import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

/**
 * Mapper for the forgot/reset password pipeline.
 * Kept separate from RegistrationMapper to preserve single responsibility.
 */
@Mapper(componentModel = "spring")
public interface PasswordResetMapper {

    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "email", source = "request.email")
    @Mapping(target = "lockKey", source = "lockKey")
    @Mapping(target = "otpCode", source = "otpCode")
    ForgotPasswordEvent toForgotPasswordEvent(ForgotPasswordRequest request, String lockKey, String otpCode);
}
