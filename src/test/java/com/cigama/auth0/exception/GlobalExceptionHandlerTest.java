package com.cigama.auth0.exception;

import com.cigama.auth0.dto.response.BaseResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler globalExceptionHandler;

    @BeforeEach
    void setUp() {
        globalExceptionHandler = new GlobalExceptionHandler();
    }

    @Test
    void handleCustomException() {
        CustomException ex = new CustomException(HttpStatus.NOT_FOUND, "User not found");

        ResponseEntity<BaseResponse<Void>> responseEntity = globalExceptionHandler.handleCustomException(ex);

        assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(404, responseEntity.getBody().getStatus());
        assertEquals("User not found", responseEntity.getBody().getMessage());
    }

    @Test
    void handleValidationException() {
        MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
        BindingResult bindingResult = mock(BindingResult.class);
        FieldError fieldError1 = new FieldError("objectName", "email", "Invalid Email format");
        FieldError fieldError2 = new FieldError("objectName", "password", "Password is required");

        when(ex.getBindingResult()).thenReturn(bindingResult);
        when(bindingResult.getFieldErrors()).thenReturn(List.of(fieldError1, fieldError2));

        ResponseEntity<BaseResponse<Void>> responseEntity = globalExceptionHandler.handleValidationException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(400, responseEntity.getBody().getStatus());
        assertEquals("Invalid Email format, Password is required", responseEntity.getBody().getMessage());
    }

    @Test
    void handleGeneralException() {
        Exception ex = new Exception("Database connection timeout");

        ResponseEntity<BaseResponse<Void>> responseEntity = globalExceptionHandler.handleGeneralException(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody());
        assertEquals(500, responseEntity.getBody().getStatus());
        assertEquals("Internal Server Error: Database connection timeout", responseEntity.getBody().getMessage());
    }
}