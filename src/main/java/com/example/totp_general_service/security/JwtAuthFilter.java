/*
Bu sınıf, JWT tabanlı kimlik doğrulama filtresi görevi görür.

Her istekte JWT token'ını kontrol eder
Token varsa kullanıcıyı doğrular
Geçerli token için kullanıcıyı güvenlik bağlamına ekler

İşlem adımları:

Authorization header'ından token çıkarır
Token'dan kullanıcı adını çıkarır
Kullanıcı detaylarını ve yetkilerini yükler
Token geçerliyse kimlik doğrulamasını yapar
Sonraki filtreye/işleme geçer
 */
package com.example.totp_general_service.security;

import com.example.totp_general_service.service.UserDetailServiceImpl;
import com.example.totp_general_service.utility.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final UserDetailServiceImpl userDetailsService;

    public JwtAuthFilter(JwtUtil jwtUtil, UserDetailServiceImpl userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            username = jwtUtil.extractUsername(token);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (jwtUtil.validateToken(token, userDetails)) {
                List<SimpleGrantedAuthority> authorities = userDetails.getAuthorities().stream()
                        .map(authority -> new SimpleGrantedAuthority(authority.getAuthority()))
                        .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, authorities);
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}