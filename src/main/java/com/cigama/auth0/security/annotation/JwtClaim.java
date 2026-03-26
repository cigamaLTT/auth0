package com.cigama.auth0.security.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to whitelist fields in CustomUserDetails that should be included
 * as claims in the JWT payload.
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface JwtClaim {
    
    /**
     * Optional value to override the claim key name in the JWT.
     * If empty, the field name will be used.
     *
     * @return key name override
     */
    String value() default "";
}
