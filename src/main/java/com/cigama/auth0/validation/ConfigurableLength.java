package com.cigama.auth0.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = ConfigurableLengthValidator.class)
@Target({ ElementType.FIELD, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
public @interface ConfigurableLength {
    String message() default "Invalid length";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    /**
     * The property key in application.properties for the MIN limit
     */
    String minKey() default "";

    /**
     * The property key in application.properties for the MAX limit
     */
    String maxKey() default "";
}
