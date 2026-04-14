package com.cigama.auth0.config;

import com.cigama.auth0.event.dto.PendingRegistrationEvent;
import com.cigama.auth0.event.listener.RegistrationStreamListener;
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
import org.springframework.beans.factory.annotation.Value;

import java.time.Duration;

@Configuration
public class RedisStreamConfig {

    @Value("${app.registration.stream-key}")
    private String registrationStreamKey;

    @Value("${app.password-reset.stream-key}")
    private String passwordResetStreamKey;

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
            com.cigama.auth0.event.listener.ForgotPasswordStreamListener listener
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
}
