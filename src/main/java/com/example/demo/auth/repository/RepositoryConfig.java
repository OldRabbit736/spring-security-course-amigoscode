package com.example.demo.auth.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class RepositoryConfig {

    private final PasswordEncoder passwordEncoder;

    @Bean
    ApplicationUserRepository getApplicationUserRepository() {
        return new FakeApplicationUserRepository(passwordEncoder);
    }
}
