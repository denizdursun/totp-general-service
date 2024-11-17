package com.example.totp_general_service.repository;

import com.example.totp_general_service.model.ServiceUser;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface ServiceUserRepository extends JpaRepository<ServiceUser, Long> {
    Optional<ServiceUser> findByUsername(String username);
}

