package com.example.totp_general_service.controller;

import com.example.totp_general_service.service.TOTPService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Value;

import java.net.URI;

@RestController
@RequestMapping("/api/totp")
public class TOTPController {
    private final TOTPService totpService;

    @Value("${spring.application.name}")
    private String appName;

    public TOTPController(TOTPService totpService) {
        this.totpService = totpService;
    }

    @PostMapping("/generate")
    public ResponseEntity<String> generateSecret(@RequestParam String username) {
        String secretKey = totpService.generateSecretKey(username);
        String qrCodeUri = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s", appName,
                username, secretKey, appName);

        return ResponseEntity.created(URI.create(qrCodeUri)).body(qrCodeUri);
    }

    @PostMapping("/validate")
    public ResponseEntity<String> validateCode(@RequestParam String username,
            @RequestParam int code) {
        boolean isValid = totpService.validateCode(username, code);
        return isValid ? ResponseEntity.ok("Doğrulama başarılı!")
                : ResponseEntity.status(401).body("Geçersiz kod!");
    }
}
