package com.example.demo.auth.config;

import com.example.demo.auth.repository.ApplicationUserRepository;
import com.example.demo.auth.repository.FakeApplicationUserRepository;
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
