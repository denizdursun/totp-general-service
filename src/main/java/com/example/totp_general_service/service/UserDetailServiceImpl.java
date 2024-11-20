/*
Spring Security'de kullanıcı kimlik doğrulama sürecini yönetir.
ServiceUserRepository üzerinden kullanıcı bilgilerini sorgular.
Bulunan kullanıcıdan username, password ve role bilgilerini alır.
Spring Security'nin User.builder() methodunu kullanarak UserDetails nesnesi oluşturur
 */
package com.example.totp_general_service.service;

import com.example.totp_general_service.model.ServiceUser;
import com.example.totp_general_service.repository.ServiceUserRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailServiceImpl implements UserDetailsService {
    private final ServiceUserRepository serviceUserRepository;

    public UserDetailServiceImpl(ServiceUserRepository userRepository) {
        this.serviceUserRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        ServiceUser user = serviceUserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Kullanıcı bulunamadı: " + username));

        // Rol isimleri otomatik olarak "ROLE_" prefix'i alacak
        return User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole())
                .build();
    }
}