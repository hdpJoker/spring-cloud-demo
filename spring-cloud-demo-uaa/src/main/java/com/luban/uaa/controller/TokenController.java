package com.luban.uaa.controller;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 自定义 Token 端点
 * 支持 password grant type 用于获取 access token
 */
@RestController
@RequestMapping("/api/token")
public class TokenController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWKSource<SecurityContext> jwkSource;

    /**
     * Password Grant - 获取 Access Token
     * 
     * 示例请求:
     * curl -X POST "http://localhost:7573/uaa/api/token" \
     *   -H "Content-Type: application/x-www-form-urlencoded" \
     *   -d "username=user_1&password=user_1"
     */
    @PostMapping(consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> getToken(
            @RequestParam String username,
            @RequestParam String password) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // 使用 AuthenticationManager 认证用户
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            if (authentication.isAuthenticated()) {
                // 生成 JWT Token
                String accessToken = generateJwtToken(authentication);
                
                response.put("access_token", accessToken);
                response.put("token_type", "Bearer");
                response.put("expires_in", 1800); // 30 分钟
                
                // 返回用户角色信息
                Set<String> roles = authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                response.put("scope", String.join(" ", roles));
                
                return ResponseEntity.ok(response);
            }
        } catch (AuthenticationException e) {
            response.put("error", "invalid_grant");
            response.put("error_description", "用户名或密码错误: " + e.getMessage());
            return ResponseEntity.status(401).body(response);
        } catch (Exception e) {
            response.put("error", "server_error");
            response.put("error_description", "服务器错误: " + e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
        
        response.put("error", "invalid_grant");
        response.put("error_description", "认证失败");
        return ResponseEntity.status(401).body(response);
    }

    /**
     * 生成 JWT Token
     */
    private String generateJwtToken(Authentication authentication) throws Exception {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(30, ChronoUnit.MINUTES);
        
        // 获取用户角色
        Set<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        
        // 获取 RSA 密钥
        JWKSet jwkSet = new JWKSet(jwkSource.get(new com.nimbusds.jose.jwk.JWKSelector(
                new com.nimbusds.jose.jwk.JWKMatcher.Builder().build()), null));
        RSAKey rsaKey = (RSAKey) jwkSet.getKeys().get(0);
        
        // 构建 JWT
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(rsaKey.getKeyID())
                .build();
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("http://localhost:7573/uaa")
                .subject(authentication.getName())
                .audience(Collections.singletonList("spring-cloud-demo"))
                .issuedAt(now)
                .expiresAt(expiresAt)
                .claim("roles", roles)
                .claim("scope", roles)
                .build();
        
        // 使用 NimbusJwtEncoder 编码
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
        Jwt jwt = encoder.encode(JwtEncoderParameters.from(header, claims));
        
        return jwt.getTokenValue();
    }
}
