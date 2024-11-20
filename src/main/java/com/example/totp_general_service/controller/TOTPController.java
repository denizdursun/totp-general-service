/*
Bu sınıf, İki Faktörlü Kimlik Doğrulama (TOTP) işlemlerini yönetir:

Gizli Anahtar Oluşturma Endpoint'i
/api/totp/generate
Kullanıcı için benzersiz TOTP anahtarı üretir
Google Authenticator için QR kodu URI'sı oluşturur

Kod Doğrulama Endpoint'i
/api/totp/validate
Kullanıcının girdiği kodu doğrular
Başarılı/başarısız sonuç döner
 */
package com.example.totp_general_service.controller;

import com.example.totp_general_service.service.TOTPService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Value;

import java.net.URI;
import java.util.Map;

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
    public ResponseEntity<String> generateSecret(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String secretKey = totpService.generateSecretKey(username);
        String qrCodeUri = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s", appName,
                username, secretKey, appName);

        return ResponseEntity.created(URI.create(qrCodeUri)).body(qrCodeUri);
    }

    @PostMapping("/validate")
    public ResponseEntity<String> validateCode(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        int code = Integer.parseInt(body.get("code"));
        boolean isValid = totpService.validateCode(username, code);
        return isValid ? ResponseEntity.ok("Doğrulama başarılı!")
                : ResponseEntity.status(401).body("Geçersiz kod!");
    }
}
