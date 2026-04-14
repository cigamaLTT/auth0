package com.cigama.auth0.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.lang.reflect.Method;

public class FieldsValueMatchValidator implements ConstraintValidator<FieldsValueMatch, Object> {

    private String field;
    private String fieldMatch;
    private String message;

    @Override
    public void initialize(FieldsValueMatch constraintAnnotation) {
        this.field = constraintAnnotation.field();
        this.fieldMatch = constraintAnnotation.fieldMatch();
        this.message = constraintAnnotation.message();
    }

    @Override
    public boolean isValid(Object value, ConstraintValidatorContext context) {
        try {
            Object fieldValue = getFieldValue(value, field);
            Object fieldMatchValue = getFieldValue(value, fieldMatch);

            boolean isValid = fieldValue != null && fieldValue.equals(fieldMatchValue);

            if (!isValid) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate(message)
                        .addPropertyNode(fieldMatch)
                        .addConstraintViolation();
            }

            return isValid;
        } catch (Exception e) {
            return false;
        }
    }

    private Object getFieldValue(Object object, String fieldName) throws Exception {
        // Handle Records (Java 14+)
        if (object.getClass().isRecord()) {
            Method method = object.getClass().getMethod(fieldName);
            return method.invoke(object);
        }
        
        // Handle standard Beans (GET methods)
        String methodName = "get" + fieldName.substring(0, 1).toUpperCase() + fieldName.substring(1);
        try {
            Method method = object.getClass().getMethod(methodName);
            return method.invoke(object);
        } catch (NoSuchMethodException e) {
            // Fallback to direct field access or other naming conventions if needed
            Method method = object.getClass().getMethod(fieldName);
            return method.invoke(object);
        }
    }
}
