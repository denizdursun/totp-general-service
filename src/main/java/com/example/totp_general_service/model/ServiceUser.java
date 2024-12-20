package com.example.totp_general_service.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "service_user")
@Data
public class ServiceUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String role; // ADMIN, USER gibi roller
}

