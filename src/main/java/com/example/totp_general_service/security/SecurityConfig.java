/*
Bu sınıf, Spring Security yapılandırmasını yönetir.

1. Güvenlik Kuralları
- `/auth/**` herkese açık
- `/api/totp/**` sadece USER ve ADMIN rolleri erişebilir
- Diğer tüm istekler kimlik doğrulaması gerektirir

2. Kimlik Doğrulama Yapılandırması
- Stateless oturum yönetimi
- JWT filtresi ekleme
- Hata yönetimi (401 Unauthorized, 403 Forbidden)

3. Şifre ve Kimlik Doğrulama Yönetimi
- BCrypt şifreleme
- Kullanıcı detay servisi ve şifre encoder'ı ile authentication manager oluşturma

Güvenlik özellikleri:
- CSRF devre dışı
- Esnek yetkilendirme kuralları
- Güvenli kimlik doğrulama mekanizması
 */
package com.example.totp_general_service.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.http.SessionCreationPolicy;
import com.example.totp_general_service.service.UserDetailServiceImpl;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
@Configuration
public class SecurityConfig {
    private final JwtAuthFilter jwtAuthFilter;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter) {
        this.jwtAuthFilter = jwtAuthFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/auth/**").permitAll()
                            .requestMatchers("/api/totp/**").hasAnyRole("USER", "ADMIN") // Rol bazlı yetkilendirme eklendi
                            .anyRequest().authenticated();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
                        })
                )
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authManager(UserDetailServiceImpl userDetailsService,
                                             PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(authProvider);
    }
}
