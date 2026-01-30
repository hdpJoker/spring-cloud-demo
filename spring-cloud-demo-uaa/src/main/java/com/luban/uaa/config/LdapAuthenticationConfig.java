package com.luban.uaa.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.ldap.core.DirContextOperations;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * LDAP 认证配置
 * 支持从 LDAP 用户属性中读取角色信息
 */
@Configuration
public class LdapAuthenticationConfig {

    @Value("${spring.ldap.urls:ldap://localhost:389}")
    private String ldapUrl;

    @Value("${spring.ldap.base:dc=luban-cae,dc=com}")
    private String ldapBase;

    @Value("${spring.ldap.username:cn=admin,dc=luban-cae,dc=com}")
    private String ldapUsername;

    @Value("${spring.ldap.password:admin}")
    private String ldapPassword;

    @Value("${ldap.user-search-base:ou=users}")
    private String userSearchBase;

    @Value("${ldap.user-search-filter:(uid={0})}")
    private String userSearchFilter;

    @Value("${ldap.role-attribute:employeeType}")
    private String roleAttribute;

    @Bean
    public LdapContextSource contextSource() {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(ldapUrl);
        contextSource.setBase(ldapBase);
        contextSource.setUserDn(ldapUsername);
        contextSource.setPassword(ldapPassword);
        contextSource.afterPropertiesSet();
        return contextSource;
    }

    @Bean
    public AuthenticationProvider ldapAuthenticationProvider(LdapContextSource contextSource) {
        // 配置绑定认证器
        BindAuthenticator authenticator = new BindAuthenticator(contextSource);
        
        // 配置用户搜索
        FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch(
                userSearchBase, 
                userSearchFilter, 
                contextSource
        );
        authenticator.setUserSearch(userSearch);

        // 自定义权限填充器，从 employeeType 属性读取角色
        LdapAuthoritiesPopulator authoritiesPopulator = new CustomLdapAuthoritiesPopulator(roleAttribute);

        LdapAuthenticationProvider provider = new LdapAuthenticationProvider(authenticator, authoritiesPopulator);
        return provider;
    }

    /**
     * 自定义 LDAP 权限填充器
     * 从用户的 employeeType 属性读取角色信息
     * 直接实现 LdapAuthoritiesPopulator 接口，避免覆盖 final 方法
     */
    public static class CustomLdapAuthoritiesPopulator implements LdapAuthoritiesPopulator {

        private final String roleAttribute;

        public CustomLdapAuthoritiesPopulator(String roleAttribute) {
            this.roleAttribute = roleAttribute;
        }

        @Override
        public Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations userData, String username) {
            Set<GrantedAuthority> authorities = new HashSet<>();

            // 从 employeeType 属性获取角色
            String[] roleValues = userData.getStringAttributes(roleAttribute);
            if (roleValues != null && roleValues.length > 0) {
                for (String role : roleValues) {
                    String normalizedRole = role.toUpperCase().trim();
                    // 确保角色带有 ROLE_ 前缀
                    if (!normalizedRole.startsWith("ROLE_")) {
                        normalizedRole = "ROLE_" + normalizedRole;
                    }
                    authorities.add(new SimpleGrantedAuthority(normalizedRole));
                }
            }

            // 如果没有从属性获取到角色，根据用户名分配默认角色
            if (authorities.isEmpty()) {
                // 根据用户名前缀分配角色
                if (username.startsWith("ldap_adm")) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_PRODUCT_ADMIN"));
                    authorities.add(new SimpleGrantedAuthority("ROLE_EDITOR"));
                    authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                } else if (username.startsWith("ldap_editor")) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_EDITOR"));
                    authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                } else {
                    // 默认 USER 角色
                    authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                }
            }

            return authorities;
        }
    }
}
