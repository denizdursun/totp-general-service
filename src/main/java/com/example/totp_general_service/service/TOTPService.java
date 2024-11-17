package com.example.totp_general_service.service;

import com.example.totp_general_service.model.User;
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
        Optional<User> existingUser = userRepository.findByUsername(username);
        if (existingUser.isPresent()) {
            return existingUser.get().getSecretKey();
        }

        GoogleAuthenticatorKey key = gAuth.createCredentials();
        User user = new User();
        user.setUsername(username);
        user.setSecretKey(key.getKey());
        userRepository.save(user);

        return key.getKey();
    }

    public boolean validateCode(String username, int code) {
        Optional<User> user = userRepository.findByUsername(username);
        return user.map(value -> gAuth.authorize(value.getSecretKey(), code)).orElse(false);
    }
}

