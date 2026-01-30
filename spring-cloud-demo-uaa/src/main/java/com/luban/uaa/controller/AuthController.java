package com.luban.uaa.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 认证 API 控制器
 * 提供 LDAP 认证验证端点
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired(required = false)
    private LdapTemplate ldapTemplate;

    /**
     * LDAP 用户认证端点
     * 用于前端 LDAP 登录表单
     */
    @PostMapping("/ldap/login")
    public ResponseEntity<Map<String, Object>> ldapLogin(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        Map<String, Object> response = new HashMap<>();

        try {
            // 使用 AuthenticationManager 进行认证（会自动尝试 LDAP 认证）
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            if (authentication.isAuthenticated()) {
                response.put("success", true);
                response.put("message", "LDAP 认证成功");
                response.put("username", authentication.getName());
                response.put("roles", authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()));
                return ResponseEntity.ok(response);
            }
        } catch (AuthenticationException e) {
            response.put("success", false);
            response.put("message", "LDAP 认证失败: " + e.getMessage());
            return ResponseEntity.status(401).body(response);
        }

        response.put("success", false);
        response.put("message", "认证失败");
        return ResponseEntity.status(401).body(response);
    }

    /**
     * 检查 LDAP 服务状态
     */
    @GetMapping("/ldap/status")
    public ResponseEntity<Map<String, Object>> ldapStatus() {
        Map<String, Object> response = new HashMap<>();
        
        if (ldapTemplate != null) {
            try {
                // 尝试查询 LDAP 根目录 - 使用显式的 AttributesMapper
                AttributesMapper<String> mapper = new AttributesMapper<String>() {
                    @Override
                    public String mapFromAttributes(Attributes attrs) throws NamingException {
                        return attrs.get("ou") != null ? attrs.get("ou").get().toString() : "unknown";
                    }
                };
                
                List<String> results = ldapTemplate.search(
                        LdapQueryBuilder.query().where("objectClass").is("organizationalUnit"),
                        mapper
                );
                response.put("available", true);
                response.put("message", "LDAP 服务可用");
                response.put("units", results);
            } catch (Exception e) {
                response.put("available", false);
                response.put("message", "LDAP 服务不可用: " + e.getMessage());
            }
        } else {
            response.put("available", false);
            response.put("message", "LDAP 模板未配置");
        }
        
        return ResponseEntity.ok(response);
    }
}
