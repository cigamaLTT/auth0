package com.cigama.auth0;

import com.cigama.auth0.repository.ClientAppRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class Auth0Application {

	public static void main(String[] args) {
		SpringApplication.run(Auth0Application.class, args);
	}

}
