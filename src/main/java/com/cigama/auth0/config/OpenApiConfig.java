package com.cigama.auth0.config;

import com.cigama.auth0.util.Constants;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Auth0 API",
                description = "Identity and Access Management REST APIs",
                version = "1.0"
        )
)
@SecurityScheme(
        name = "bearerAuth",
        description = "JWT authentication. Please insert the Bearer token below.",
        scheme = "bearer",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER
)
public class OpenApiConfig {

    @Bean
    public OperationCustomizer hideAuthorizationHeaderParam() {
        return (operation, handlerMethod) -> {
            if (operation.getParameters() != null) {
                operation.getParameters().removeIf(p ->
                        "header".equalsIgnoreCase(p.getIn()) && Constants.AUTHORIZATION_HEADER.equalsIgnoreCase(p.getName())
                );
            }
            return operation;
        };
    }
}
