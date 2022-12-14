package com.example.demo.auth.repository;

import com.example.demo.auth.domain.ApplicationUser;

import java.util.Optional;

public interface ApplicationUserRepository {

    Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
