package com.example.totp_general_service.repository;

import com.example.totp_general_service.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Users, Long> {
    Optional<Users> findByUsername(String username);
}
