package com.luban.uaa.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

/**
 * GitHub OAuth2 用户信息处理服务
 * 题目要求：GitHub 登录后给 EDITOR 角色
 */
@Service
public class GitHubOAuth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);

        // GitHub 登录用户默认分配 EDITOR 角色（题目要求）
        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_EDITOR"));
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        
        // 合并原有权限
        authorities.addAll(oauth2User.getAuthorities());

        // 使用 login 属性作为用户名
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();

        return new DefaultOAuth2User(authorities, oauth2User.getAttributes(), userNameAttributeName);
    }
}
