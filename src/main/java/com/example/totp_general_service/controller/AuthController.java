/*
Bu sınıf, kullanıcı kimlik doğrulama ve kayıt işlemlerini yönetir:

Kayıt Endpoint'i (/auth/register)
Yeni kullanıcı kaydı
Varsayılan rol "USER"
Parolayı güvenli şekilde şifreleme

Giriş Endpoint'i (/auth/login)
Kullanıcı kimlik doğrulaması
JWT token üretme
Kullanıcı yetkilerini token'a ekleme
 */
package com.example.totp_general_service.controller;

import com.example.totp_general_service.dto.AuthRequest;
import com.example.totp_general_service.model.ServiceUser;
import com.example.totp_general_service.service.ServiceUserService;
import com.example.totp_general_service.utility.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;
    private final ServiceUserService serviceUserService;

    public AuthController(AuthenticationManager authManager, JwtUtil jwtUtil, ServiceUserService serviceUserService) {
        this.authManager = authManager;
        this.jwtUtil = jwtUtil;
        this.serviceUserService = serviceUserService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest request) {
        ServiceUser serviceUser = new ServiceUser();
        serviceUser.setUsername(request.getUsername());
        serviceUser.setPassword(request.getPassword());
        serviceUser.setRole(request.getRole() != null ? request.getRole() : "USER"); // Varsayılan rol USER
        serviceUserService.saveUser(serviceUser);
        return ResponseEntity.ok("Servis kullanıcısı başarılı bir şekilde kaydedildi");
    }

    @PostMapping("/login")
    public String login(@RequestBody AuthRequest request) {
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        // Kullanıcının yetkilerini authentication nesnesinden al
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        return jwtUtil.generateToken(request.getUsername(), authorities);
    }
}