package com.luban.uaa.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 自定义 OAuth2 Token 增强器
 * 将用户角色信息添加到 JWT Token 中
 */
@Component
public class CustomOAuth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();
        
        if (principal != null && principal.getAuthorities() != null) {
            // 获取用户的所有角色
            Set<String> roles = principal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());

            // 将角色添加到 JWT claims 中
            context.getClaims().claim("roles", roles);
            
            // 同时添加到 scope 中以保持兼容性
            Set<String> scopes = new HashSet<>();
            for (String role : roles) {
                scopes.add(role.replace("ROLE_", ""));
            }
            
            // 获取现有的 scope 并合并
            Object existingScope = context.getClaims().build().getClaim("scope");
            if (existingScope instanceof Set) {
                @SuppressWarnings("unchecked")
                Set<String> existingScopes = (Set<String>) existingScope;
                scopes.addAll(existingScopes);
            }
            
            context.getClaims().claim("scope", scopes);
        }
    }
}
