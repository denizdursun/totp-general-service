/*
Bu sınıf, İki Faktörlü Kimlik Doğrulama (TOTP) için kullanılır.

Gizli Anahtar Oluşturma

Kullanıcı için benzersiz TOTP anahtarı üretir
Eğer kullanıcı zaten varsa, mevcut anahtarı döndürür

Kod Doğrulama

Kullanıcının girdiği kodu doğrular
Google Authenticator kütüphanesi kullanır
 */
package com.example.totp_general_service.service;

import com.example.totp_general_service.model.Users;
import com.example.totp_general_service.repository.UserRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class TOTPService {
    private final UserRepository userRepository;
    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();

    public TOTPService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public String generateSecretKey(String username) {
        Optional<Users> existingUser = userRepository.findByUsername(username);
        if (existingUser.isPresent()) {
            return existingUser.get().getSecretKey();
        }

        GoogleAuthenticatorKey key = gAuth.createCredentials();
        Users user = new Users();
        user.setUsername(username);
        user.setSecretKey(key.getKey());
        userRepository.save(user);

        return key.getKey();
    }

    public boolean validateCode(String username, int code) {
        Optional<Users> user = userRepository.findByUsername(username);
        return user.map(value -> gAuth.authorize(value.getSecretKey(), code)).orElse(false);
    }
}

