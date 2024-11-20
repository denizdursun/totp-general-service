/*
Bu sınıf, kullanıcı kayıt ve güvenlik işlemlerini yönetir:

Temel İşlevleri

Kullanıcı kaydı
Parolaları güvenli şekilde şifreleme
Varsayılan rol atama

Güvenlik Özellikleri

BCrypt ile parola hash'leme
Rol ataması (belirtilmezse "USER")
Kullanıcıyı veritabanına kaydetme
 */
package com.example.totp_general_service.service;

import com.example.totp_general_service.model.ServiceUser;
import com.example.totp_general_service.repository.ServiceUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class ServiceUserService {
    private final ServiceUserRepository serviceUserRepository;
    private final PasswordEncoder passwordEncoder;

    public ServiceUserService(ServiceUserRepository serviceUserRepository, PasswordEncoder passwordEncoder) {
        this.serviceUserRepository = serviceUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public ServiceUser saveUser(ServiceUser serviceUser){
        // Parolayı hash'le
        serviceUser.setPassword(passwordEncoder.encode(serviceUser.getPassword()));
        // Role ataması (eğer yoksa)
        if (serviceUser.getRole() == null) {
            serviceUser.setRole("USER");
        }
        return serviceUserRepository.save(serviceUser);
    }
}
