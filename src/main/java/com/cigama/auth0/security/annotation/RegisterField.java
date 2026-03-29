package com.cigama.auth0.security.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to whitelist fields that can be populated via Reflection from RegisterRequest.
 * Prevents mass-assignment vulnerabilities.
 * Method: AuthServiceImpl.register()
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RegisterField {
}
