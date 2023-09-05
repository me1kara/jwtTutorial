package com.han.jwtTuto;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication
public class JwtTutorialApplication {
	public static void main(String[] args) {
		SpringApplication.run(JwtTutorialApplication.class, args);
	}

}
