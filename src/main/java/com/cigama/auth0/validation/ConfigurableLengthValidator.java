package com.cigama.auth0.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

@Component
public class ConfigurableLengthValidator implements ConstraintValidator<ConfigurableLength, String> {

    private final Environment environment;

    public ConfigurableLengthValidator(Environment environment) {
        this.environment = environment;
    }

    private String minKey;
    private String maxKey;

    @Override
    public void initialize(ConfigurableLength constraintAnnotation) {
        this.minKey = constraintAnnotation.minKey();
        this.maxKey = constraintAnnotation.maxKey();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null) {
            return true;
        }

        int length = value.length();
        Integer min = getLimit(minKey, 0);
        Integer max = getLimit(maxKey, Integer.MAX_VALUE);

        if (length < min || length > max) {
            context.disableDefaultConstraintViolation();
            String message;
            if (max == Integer.MAX_VALUE) {
                message = String.format("Length must be at least %d characters", min);
            } else if (min == 0) {
                message = String.format("Length must be at most %d characters", max);
            } else {
                message = String.format("Length must be between %d and %d characters", min, max);
            }
            context.buildConstraintViolationWithTemplate(message)
                   .addConstraintViolation();
            return false;
        }

        return true;
    }

    private Integer getLimit(String key, int defaultValue) {
        if (key == null || key.isBlank()) {
            return defaultValue;
        }
        String propertyValue = environment.getProperty(key);
        if (propertyValue == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(propertyValue);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
