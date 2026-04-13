package com.cigama.auth0.exception;

import com.cigama.auth0.dto.response.BaseResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // --- Exception Handlers ---


    /**
     * Handles business logic exceptions.
     */
    @ExceptionHandler(CustomException.class)
    public ResponseEntity<BaseResponse<Void>> handleCustomException(CustomException ex) {
        BaseResponse<Void> response = new BaseResponse<>(ex.getStatus().value(), ex.getMessage(), null);
        return new ResponseEntity<>(response, ex.getStatus());
    }

    /**
     * Handles bean validation errors.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<BaseResponse<Void>> handleValidationException(MethodArgumentNotValidException ex) {
        String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(FieldError::getDefaultMessage)
                .collect(Collectors.joining(", "));

        BaseResponse<Void> response = new BaseResponse<>(HttpStatus.BAD_REQUEST.value(), errorMessage, null);
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    /**
     * Fallback handler for all uncaught exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<BaseResponse<Void>> handleGeneralException(Exception ex) {
        String message = "Internal Server Error" + (ex.getMessage() != null ? ": " + ex.getMessage() : "");
        BaseResponse<Void> response = new BaseResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(), message, null);
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
