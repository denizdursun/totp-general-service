/*
JWT Oluşturma

Kullanıcı adı ve yetkilerini içeren token üretir
Token'a süre sınırı koyar (1 saat 40 dakika)

Güvenli Anahtar Yönetimi

Rastgele, güvenli bir şifreleme anahtarı üretir
Anahtarı dosyada saklar/yükler

Token Doğrulama İşlemleri

Token'ın geçerliliğini kontrol eder
Kullanıcı adını ve rollerini token'dan çıkarır
 */
package com.example.totp_general_service.utility;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;

@Component
public class JwtUtil {
    private final SecretKey key;
    private final String secretPath;

    public JwtUtil(@Value("${jwt.secret.path}") String secretPath) {
        this.secretPath = secretPath;
        this.key = loadOrGenerateKey();
    }

    private SecretKey loadOrGenerateKey() {
        try {
            Path path = Paths.get(secretPath);

            // Eğer key dosyası varsa, oku
            if (Files.exists(path)) {
                byte[] keyBytes = Files.readAllBytes(path);
                return Keys.hmacShaKeyFor(Base64.getDecoder().decode(keyBytes));
            }

            // Key dosyası yoksa, yeni key oluştur
            byte[] keyBytes = generateSecureKey();

            // Key'i dosyaya kaydet
            Files.write(path, Base64.getEncoder().encode(keyBytes));

            return Keys.hmacShaKeyFor(keyBytes);

        } catch (IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException("JWT secretkey'i yüklenemedi veya oluşturulamadı", e);
        }
    }

    private byte[] generateSecureKey() throws NoSuchAlgorithmException {
        // Güvenli random sayı üreteci
        SecureRandom secureRandom = new SecureRandom();

        // 256-bit (32 byte) key oluştur
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);

        return key;
    }

    public String generateToken(String username, Collection<? extends GrantedAuthority> authorities) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 600 * 600))
                .signWith(key)
                .compact();
    }

    // Rolleri token'dan çıkarmak için yeni metod
    public List<String> extractRoles(String token) {
        Claims claims = getClaims(token);
        return claims.get("roles", List.class);
    }

    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    public boolean isTokenValid(String token) {
        return getClaims(token).getExpiration().after(new Date());
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }

    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}