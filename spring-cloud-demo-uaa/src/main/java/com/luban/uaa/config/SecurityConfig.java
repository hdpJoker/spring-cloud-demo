package com.luban.uaa.config;

import com.luban.uaa.user.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;

@Configuration
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationProvider ldapAuthenticationProvider;

    public SecurityConfig(CustomUserDetailsService userDetailsService, 
                          PasswordEncoder passwordEncoder,
                          AuthenticationProvider ldapAuthenticationProvider) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.ldapAuthenticationProvider = ldapAuthenticationProvider;
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        // 创建包含多个 AuthenticationProvider 的 AuthenticationManager
        // 优先级：数据库认证 -> LDAP 认证
        return new ProviderManager(Arrays.asList(
                daoAuthenticationProvider(),
                ldapAuthenticationProvider
        ));
    }
}
