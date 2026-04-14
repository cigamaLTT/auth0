package com.cigama.auth0.config;

import com.cigama.auth0.event.dto.PendingRegistrationEvent;
import com.cigama.auth0.event.listener.RegistrationStreamListener;
import com.cigama.auth0.event.listener.AccountLockoutListener;
import com.cigama.auth0.event.listener.SecuritySettingOtpListener;
import com.cigama.auth0.event.listener.SecuritySuccessEventListener;
import com.cigama.auth0.event.listener.LoginTrackerStreamListener;
import com.cigama.auth0.event.listener.ForgotPasswordStreamListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.stream.Consumer;
import org.springframework.data.redis.connection.stream.ObjectRecord;
import org.springframework.data.redis.connection.stream.ReadOffset;
import org.springframework.data.redis.connection.stream.StreamOffset;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJacksonJsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.data.redis.stream.StreamMessageListenerContainer;
import org.springframework.data.redis.stream.StreamMessageListenerContainer.StreamMessageListenerContainerOptions;
import org.springframework.data.redis.stream.Subscription;
import tools.jackson.databind.ObjectMapper;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.beans.factory.annotation.Value;
import java.time.Duration;

@Configuration
public class RedisStreamConfig {

    @Bean
    public AsyncTaskExecutor redisStreamExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(25);
        executor.setThreadNamePrefix("redis-stream-");
        executor.initialize();
        return executor;
    }

    @Value("${app.registration.stream-key}")
    private String registrationStreamKey;

    @Value("${app.password-reset.stream-key}")
    private String passwordResetStreamKey;

    @Value("${app.login.stream-key:auth:login-tracker:stream}")
    private String loginTrackerStreamKey;

    @Value("${app.security.stream-key:auth:security:stream}")
    private String securityStreamKey;

    public static final String REGISTRATION_GROUP = "registration-group";
    public static final String FORGOT_PASSWORD_GROUP = "forgot-password-group";


    @Bean
    public RedisTemplate<String, Object> streamRedisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        // String serializer prevents double-quoting which breaks Lua scripts and Streams
        template.setValueSerializer(new StringRedisSerializer());
        template.setHashValueSerializer(new StringRedisSerializer());
        
        return template;
    }

    @Bean
    public StreamMessageListenerContainer<String, ObjectRecord<String, String>> registrationStreamListenerContainer
            (
                RedisConnectionFactory factory,
                RegistrationStreamListener listener
            ) {
        StreamMessageListenerContainerOptions<String, ObjectRecord<String, String>> options =
                StreamMessageListenerContainerOptions.builder()
                        .pollTimeout(Duration.ofMillis(100))
                        .targetType(String.class)
                        .build();

        StreamMessageListenerContainer<String, ObjectRecord<String, String>> container =
                StreamMessageListenerContainer.create(factory, options);

        container.receive(StreamOffset.create(registrationStreamKey, ReadOffset.lastConsumed()), listener);


        container.start();
        return container;
    }

    @Bean
    public StreamMessageListenerContainer<String, ObjectRecord<String, String>> forgotPasswordStreamListenerContainer(
            RedisConnectionFactory factory,
            ForgotPasswordStreamListener listener
    ) {
        StreamMessageListenerContainerOptions<String, ObjectRecord<String, String>> options =
                StreamMessageListenerContainerOptions.builder()
                        .pollTimeout(Duration.ofMillis(100))
                        .targetType(String.class)
                        .build();

        StreamMessageListenerContainer<String, ObjectRecord<String, String>> container =
                StreamMessageListenerContainer.create(factory, options);

        container.receive(StreamOffset.create(passwordResetStreamKey, ReadOffset.lastConsumed()), listener);

        container.start();
        return container;
    }

    @Bean
    public StreamMessageListenerContainer<String, ObjectRecord<String, String>> securityStreamListenerContainer(
            RedisConnectionFactory factory,
            AccountLockoutListener lockoutListener,
            SecuritySettingOtpListener settingOtpListener,
            SecuritySuccessEventListener successListener
    ) {
        StreamMessageListenerContainerOptions<String, ObjectRecord<String, String>> options =
                StreamMessageListenerContainerOptions.builder()
                        .pollTimeout(Duration.ofMillis(100))
                        .executor(redisStreamExecutor())
                        .targetType(String.class)
                        .build();

        StreamMessageListenerContainer<String, ObjectRecord<String, String>> container =
                StreamMessageListenerContainer.create(factory, options);

        container.receive(StreamOffset.create(securityStreamKey, ReadOffset.lastConsumed()), lockoutListener);
        container.receive(StreamOffset.create(securityStreamKey, ReadOffset.lastConsumed()), settingOtpListener);
        container.receive(StreamOffset.create(securityStreamKey, ReadOffset.lastConsumed()), successListener);

        container.start();
        return container;
    }

    @Bean
    public StreamMessageListenerContainer<String, ObjectRecord<String, String>> loginTrackerStreamListenerContainer(
            RedisConnectionFactory factory, LoginTrackerStreamListener listener) {
        return createContainer(factory, loginTrackerStreamKey, listener);
    }

    private StreamMessageListenerContainer<String, ObjectRecord<String, String>> createContainer(
            RedisConnectionFactory factory, String streamKey, org.springframework.data.redis.stream.StreamListener<String, ObjectRecord<String, String>> listener) {
        StreamMessageListenerContainerOptions<String, ObjectRecord<String, String>> options =
                StreamMessageListenerContainerOptions.builder()
                        .pollTimeout(Duration.ofMillis(100))
                        .executor(redisStreamExecutor())
                        .targetType(String.class)
                        .build();

        StreamMessageListenerContainer<String, ObjectRecord<String, String>> container =
                StreamMessageListenerContainer.create(factory, options);

        container.receive(StreamOffset.create(streamKey, ReadOffset.lastConsumed()), listener);
        container.start();
        return container;
    }
}

