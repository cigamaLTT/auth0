package com.cigama.auth0.validation;

import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ConfigurableLengthValidator Tests")
class ConfigurableLengthValidatorTest {

    @Mock
    private Environment environment;

    @Mock
    private ConstraintValidatorContext context;

    @Mock
    private ConstraintValidatorContext.ConstraintViolationBuilder builder;

    @Mock
    private ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderCustomizableContext nodeBuilder;

    @InjectMocks
    private ConfigurableLengthValidator validator;

    @Mock
    private ConfigurableLength annotation;

    @BeforeEach
    void setUp() {
        lenient().when(annotation.minKey()).thenReturn("auth.min.len");
        lenient().when(annotation.maxKey()).thenReturn("auth.max.len");
        validator.initialize(annotation);
    }

    @Test
    @DisplayName("Should return true when value is null")
    void shouldReturnTrueWhenValueIsNull() {
        assertTrue(validator.isValid(null, context));
    }

    @Nested
    @DisplayName("Bounds Validation Tests")
    class BoundsValidationTests {

        @Test
        @DisplayName("Should return true when length is within range")
        void shouldReturnTrueWhenLengthIsWithinRange() {
            when(environment.getProperty("auth.min.len")).thenReturn("5");
            when(environment.getProperty("auth.max.len")).thenReturn("10");

            assertTrue(validator.isValid("123456", context));
            assertTrue(validator.isValid("12345", context));
            assertTrue(validator.isValid("1234567890", context));
        }

        @Test
        @DisplayName("Should return false when length is below min")
        void shouldReturnFalseWhenLengthIsBelowMin() {
            when(environment.getProperty("auth.min.len")).thenReturn("5");
            when(environment.getProperty("auth.max.len")).thenReturn("10");
            setupMockContext();

            assertFalse(validator.isValid("1234", context));
            verify(context).buildConstraintViolationWithTemplate("Length must be between 5 and 10 characters");
        }

        @Test
        @DisplayName("Should return false when length is above max")
        void shouldReturnFalseWhenLengthIsAboveMax() {
            when(environment.getProperty("auth.min.len")).thenReturn("5");
            when(environment.getProperty("auth.max.len")).thenReturn("10");
            setupMockContext();

            assertFalse(validator.isValid("12345678901", context));
            verify(context).buildConstraintViolationWithTemplate("Length must be between 5 and 10 characters");
        }
    }

    @Nested
    @DisplayName("Message Generation Tests")
    class MessageGenerationTests {

        @Test
        @DisplayName("Should generate 'at least' message when only minKey is provided")
        void shouldGenerateAtLeastMessageWhenOnlyMinKeyIsProvided() {
            when(annotation.minKey()).thenReturn("auth.min.len");
            when(annotation.maxKey()).thenReturn("");
            validator.initialize(annotation);

            when(environment.getProperty("auth.min.len")).thenReturn("8");
            setupMockContext();

            assertFalse(validator.isValid("short", context));
            verify(context).buildConstraintViolationWithTemplate("Length must be at least 8 characters");
        }

        @Test
        @DisplayName("Should generate 'at most' message when only maxKey is provided")
        void shouldGenerateAtMostMessageWhenOnlyMaxKeyIsProvided() {
            when(annotation.minKey()).thenReturn("");
            when(annotation.maxKey()).thenReturn("auth.max.len");
            validator.initialize(annotation);

            when(environment.getProperty("auth.max.len")).thenReturn("5");
            setupMockContext();

            assertFalse(validator.isValid("too_long", context));
            verify(context).buildConstraintViolationWithTemplate("Length must be at most 5 characters");
        }
    }

    @Nested
    @DisplayName("Fallback and Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should use default values when properties are missing")
        void shouldUseDefaultsWhenPropertiesAreMissing() {
            when(environment.getProperty(anyString())).thenReturn(null);
            assertTrue(validator.isValid("any length will pass", context));
        }

        @Test
        @DisplayName("Should use default values when properties are not numbers")
        void shouldUseDefaultsWhenPropertiesAreInvalid() {
            when(environment.getProperty("auth.min.len")).thenReturn("invalid");
            when(environment.getProperty("auth.max.len")).thenReturn("invalid");

            assertTrue(validator.isValid("any length will pass", context));
        }
    }

    private void setupMockContext() {
        when(context.buildConstraintViolationWithTemplate(anyString())).thenReturn(builder);
        when(builder.addConstraintViolation()).thenReturn(context);
    }
}
