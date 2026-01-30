package com.luban.product.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 资源服务器配置
 * 配置 JWT 解码和权限转换
 */
@Configuration
public class ResourceServerConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri:http://localhost:8081/uaa/oauth2/jwks}")
    private String jwkSetUri;

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new CustomJwtGrantedAuthoritiesConverter());
        return converter;
    }

    /**
     * 自定义 JWT 权限转换器
     * 从 JWT 的 roles 和 scope claims 中提取权限
     */
    public static class CustomJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            List<GrantedAuthority> authorities = new ArrayList<>();

            // 1. 从 "roles" claim 中提取角色
            Object rolesClaim = jwt.getClaim("roles");
            if (rolesClaim instanceof Collection) {
                @SuppressWarnings("unchecked")
                Collection<String> roles = (Collection<String>) rolesClaim;
                for (String role : roles) {
                    // 确保角色有 ROLE_ 前缀
                    if (role.startsWith("ROLE_")) {
                        authorities.add(new SimpleGrantedAuthority(role));
                    } else {
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                    }
                }
            }

            // 2. 从 "scope" claim 中提取权限（作为备选）
            Object scopeClaim = jwt.getClaim("scope");
            if (scopeClaim instanceof Collection) {
                @SuppressWarnings("unchecked")
                Collection<String> scopes = (Collection<String>) scopeClaim;
                for (String scope : scopes) {
                    // 将 scope 也转换为 ROLE_XXX 格式（如果还没有添加）
                    String authority = "ROLE_" + scope.toUpperCase();
                    SimpleGrantedAuthority grantedAuthority = new SimpleGrantedAuthority(authority);
                    if (!authorities.contains(grantedAuthority)) {
                        authorities.add(grantedAuthority);
                    }
                }
            } else if (scopeClaim instanceof String) {
                // 处理空格分隔的 scope 字符串
                String[] scopes = ((String) scopeClaim).split(" ");
                for (String scope : scopes) {
                    if (!scope.isEmpty()) {
                        String authority = "ROLE_" + scope.toUpperCase();
                        SimpleGrantedAuthority grantedAuthority = new SimpleGrantedAuthority(authority);
                        if (!authorities.contains(grantedAuthority)) {
                            authorities.add(grantedAuthority);
                        }
                    }
                }
            }

            return authorities;
        }
    }
}
