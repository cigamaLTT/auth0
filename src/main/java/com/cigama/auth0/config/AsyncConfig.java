package com.cigama.auth0.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

@Configuration
@EnableAsync
public class AsyncConfig {
    // This enables the @Async functionality.
    // Since spring.threads.virtual.enabled=true is set in properties,
    // the default task executor will use Virtual Threads.
}
