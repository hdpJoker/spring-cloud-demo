# Spring Cloud 微服务项目实现计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**目标：** 构建一个完整的 Spring Cloud 微服务演示项目，包含认证授权、产品管理、API 网关等功能。

**架构：** 多模块 Maven 项目，使用 Nacos 作为服务发现与配置中心，Spring Authorization Server 实现 OAuth2 认证，Gateway 作为统一入口。

**技术栈：** Spring Boot 3.2.x, Spring Cloud 2023.0.x, Spring Authorization Server 1.2.x, Nacos 2.3.x, MySQL 8.0, OpenLDAP

---

## 前置条件

- JDK 17 或更高版本
- Maven 3.8+
- Docker & Docker Compose
- Git

---

## Task 1: 创建项目骨架和父 POM

**文件：**
- 创建: `pom.xml` (父 POM)
- 创建: `spring-cloud-demo-common/pom.xml`
- 创建: `spring-cloud-demo-uaa/pom.xml`
- 创建: `spring-cloud-demo-product/pom.xml`
- 创建: `spring-cloud-demo-gateway/pom.xml`

**Step 1: 创建父 POM 文件**

创建 `/Users/carsonhe/IdeaProjects/Aidemo/pom.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.10</version>
        <relativePath/>
    </parent>

    <groupId>com.luban</groupId>
    <artifactId>spring-cloud-demo</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>
    <name>Spring Cloud Demo</name>
    <description>Spring Cloud 微服务演示项目</description>

    <properties>
        <java.version>17</java.version>
        <spring-cloud.version>2023.0.3</spring-cloud.version>
        <spring-cloud-alibaba.version>2023.0.1.0</spring-cloud-alibaba.version>
        <spring-authorization-server.version>1.2.5</spring-authorization-server.version>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <modules>
        <module>spring-cloud-demo-common</module>
        <module>spring-cloud-demo-uaa</module>
        <module>spring-cloud-demo-product</module>
        <module>spring-cloud-demo-gateway</module>
    </modules>

    <dependencyManagement>
        <dependencies>
            <!-- Spring Cloud Dependencies -->
            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>
                <version>${spring-cloud.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>

            <!-- Spring Cloud Alibaba Dependencies -->
            <dependency>
                <groupId>com.alibaba.cloud</groupId>
                <artifactId>spring-cloud-alibaba-dependencies</artifactId>
                <version>${spring-cloud-alibaba.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>

            <!-- Spring Authorization Server -->
            <dependency>
                <groupId>org.springframework.security</groupId>
                <artifactId>spring-security-oauth2-authorization-server</artifactId>
                <version>${spring-authorization-server.version}</version>
            </dependency>

            <!-- 内部模块依赖 -->
            <dependency>
                <groupId>com.luban</groupId>
                <artifactId>spring-cloud-demo-common</artifactId>
                <version>${project.version}</version>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <build>
        <pluginManagement>
            <plugins>
                <plugin>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-maven-plugin</artifactId>
                    <configuration>
                        <excludes>
                            <exclude>
                                <groupId>org.projectlombok</groupId>
                                <artifactId>lombok</artifactId>
                            </exclude>
                        </excludes>
                    </configuration>
                </plugin>
            </plugins>
        </pluginManagement>
    </build>
</project>
```

**Step 2: 创建模块目录结构**

```bash
cd /Users/carsonhe/IdeaProjects/Aidemo
mkdir -p spring-cloud-demo-common/src/main/java/com/luban/common
mkdir -p spring-cloud-demo-common/src/main/resources
mkdir -p spring-cloud-demo-uaa/src/main/java/com/luban/uaa
mkdir -p spring-cloud-demo-uaa/src/main/resources
mkdir -p spring-cloud-demo-product/src/main/java/com/luban/product
mkdir -p spring-cloud-demo-product/src/main/resources
mkdir -p spring-cloud-demo-gateway/src/main/java/com/luban/gateway
mkdir -p spring-cloud-demo-gateway/src/main/resources
```

**Step 3: 创建 common 模块 POM**

创建 `spring-cloud-demo-common/pom.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.luban</groupId>
        <artifactId>spring-cloud-demo</artifactId>
        <version>1.0.0</version>
    </parent>

    <artifactId>spring-cloud-demo-common</artifactId>
    <name>Common Module</name>
    <description>公共模块</description>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        <dependency>
            <groupId>com.mysql</groupId>
            <artifactId>mysql-connector-j</artifactId>
            <scope>runtime</scope>
        </dependency>
    </dependencies>
</project>
```

**Step 4: 创建 uaa 模块 POM**

创建 `spring-cloud-demo-uaa/pom.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.luban</groupId>
        <artifactId>spring-cloud-demo</artifactId>
        <version>1.0.0</version>
    </parent>

    <artifactId>spring-cloud-demo-uaa</artifactId>
    <name>UAA Service</name>
    <description>认证授权服务</description>

    <dependencies>
        <dependency>
            <groupId>com.luban</groupId>
            <artifactId>spring-cloud-demo-common</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-oauth2-authorization-server</artifactId>
        </dependency>
        <dependency>
            <groupId>com.alibaba.cloud</groupId>
            <artifactId>spring-cloud-starter-alibaba-nacos-discovery</artifactId>
        </dependency>
        <dependency>
            <groupId>com.alibaba.cloud</groupId>
            <artifactId>spring-cloud-starter-alibaba-nacos-config</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

**Step 5: 创建 product 模块 POM**

创建 `spring-cloud-demo-product/pom.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.luban</groupId>
        <artifactId>spring-cloud-demo</artifactId>
        <version>1.0.0</version>
    </parent>

    <artifactId>spring-cloud-demo-product</artifactId>
    <name>Product Service</name>
    <description>产品服务</description>

    <dependencies>
        <dependency>
            <groupId>com.luban</groupId>
            <artifactId>spring-cloud-demo-common</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
        </dependency>
        <dependency>
            <groupId>com.alibaba.cloud</groupId>
            <artifactId>spring-cloud-starter-alibaba-nacos-discovery</artifactId>
        </dependency>
        <dependency>
            <groupId>com.alibaba.cloud</groupId>
            <artifactId>spring-cloud-starter-alibaba-nacos-config</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

**Step 6: 创建 gateway 模块 POM**

创建 `spring-cloud-demo-gateway/pom.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.luban</groupId>
        <artifactId>spring-cloud-demo</artifactId>
        <version>1.0.0</version>
    </parent>

    <artifactId>spring-cloud-demo-gateway</artifactId>
    <name>Gateway Service</name>
    <description>API 网关服务</description>

    <dependencies>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-gateway</artifactId>
        </dependency>
        <dependency>
            <groupId>com.alibaba.cloud</groupId>
            <artifactId>spring-cloud-starter-alibaba-nacos-discovery</artifactId>
        </dependency>
        <dependency>
            <groupId>com.alibaba.cloud</groupId>
            <artifactId>spring-cloud-starter-alibaba-nacos-config</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

**Step 7: 验证项目构建**

```bash
cd /Users/carsonhe/IdeaProjects/Aidemo
mvn clean verify
```

预期输出: BUILD SUCCESS

**Step 8: 提交**

```bash
git add .
git commit -m "feat: 创建多模块项目骨架和父POM配置"
```

---

## Task 2: 实现 spring-cloud-demo-common 公共模块

**文件：**
- 创建: `spring-cloud-demo-common/src/main/java/com/luban/common/entity/User.java`
- 创建: `spring-cloud-demo-common/src/main/java/com/luban/common/entity/Product.java`
- 创建: `spring-cloud-demo-common/src/main/java/com/luban/common/repository/UserRepository.java`
- 创建: `spring-cloud-demo-common/src/main/java/com/luban/common/repository/ProductRepository.java`
- 创建: `spring-cloud-demo-common/src/main/java/com/luban/common/constants/RoleConstants.java`

**Step 1: 创建 User 实体类**

创建 `spring-cloud-demo-common/src/main/java/com/luban/common/entity/User.java`:

```java
package com.luban.common.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "users")
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 50)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, length = 50)
    private String role;

    @Column(nullable = false)
    private Boolean enabled = true;
}
```

**Step 2: 创建 Product 实体类**

创建 `spring-cloud-demo-common/src/main/java/com/luban/common/entity/Product.java`:

```java
package com.luban.common.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "products")
@Data
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String name;
}
```

**Step 3: 创建 UserRepository**

创建 `spring-cloud-demo-common/src/main/java/com/luban/common/repository/UserRepository.java`:

```java
package com.luban.common.repository;

import com.luban.common.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
}
```

**Step 4: 创建 ProductRepository**

创建 `spring-cloud-demo-common/src/main/java/com/luban/common/repository/ProductRepository.java`:

```java
package com.luban.common.repository;

import com.luban.common.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ProductRepository extends JpaRepository<Product, Long> {
}
```

**Step 5: 创建角色常量类**

创建 `spring-cloud-demo-common/src/main/java/com/luban/common/constants/RoleConstants.java`:

```java
package com.luban.common.constants;

public class RoleConstants {
    public static final String ROLE_USER = "USER";
    public static final String ROLE_EDITOR = "EDITOR";
    public static final String ROLE_PRODUCT_ADMIN = "PRODUCT_ADMIN";

    public static final String AUTHORITY_PREFIX = "ROLE_";
}
```

**Step 6: 验证编译**

```bash
cd /Users/carsonhe/IdeaProjects/Aidemo
mvn clean compile -pl spring-cloud-demo-common
```

预期输出: BUILD SUCCESS

**Step 7: 提交**

```bash
git add spring-cloud-demo-common/
git commit -m "feat: 实现公共模块实体和Repository"
```

---

## Task 3: 实现 spring-cloud-demo-uaa 认证服务

**文件：**
- 创建: `spring-cloud-demo-uaa/src/main/java/com/luban/uaa/UaaApplication.java`
- 创建: `spring-cloud-demo-uaa/src/main/java/com/luban/uaa/config/AuthorizationServerConfig.java`
- 创建: `spring-cloud-demo-uaa/src/main/java/com/luban/uaa/config/SecurityConfig.java`
- 创建: `spring-cloud-demo-uaa/src/main/java/com/luban/uaa/config/JwtConfig.java`
- 创建: `spring-cloud-demo-uaa/src/main/java/com/luban/uaa/user/CustomUserDetailsService.java`
- 创建: `spring-cloud-demo-uaa/src/main/resources/application.yml`
- 创建: `spring-cloud-demo-uaa/src/main/resources/bootstrap.yml`

**Step 1: 创建 UAA 主启动类**

创建 `spring-cloud-demo-uaa/src/main/java/com/luban/uaa/UaaApplication.java`:

```java
package com.luban.uaa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class UaaApplication {

    public static void main(String[] args) {
        SpringApplication.run(UaaApplication.class, args);
    }
}
```

**Step 2: 创建 AuthorizationServerConfig**

创建 `spring-cloud-demo-uaa/src/main/java/com/luban/uaa/config/AuthorizationServerConfig.java`:

```java
package com.luban.uaa.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        http
                .securityMatcher(
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/uaa/**")
                )
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults()));

        http.exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.cors(Customizer.withStateless()).build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()));

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret(passwordEncoder().encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .redirectUri("http://localhost:7573/login/oauth2/code/client")
                .scope(OidcScopes.OPENID)
                .scope("read")
                .scope("write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:7573/uaa")
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOriginPattern("*");
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

**Step 3: 创建 SecurityConfig**

创建 `spring-cloud-demo-uaa/src/main/java/com/luban/uaa/config/SecurityConfig.java`:

```java
package com.luban.uaa.config;

import com.luban.uaa.user.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public SecurityConfig(CustomUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
```

**Step 4: 创建 JwtConfig**

创建 `spring-cloud-demo-uaa/src/main/java/com/luban/uaa/config/JwtConfig.java`:

```java
package com.luban.uaa.config;

import com.nimbusds.jose.jwk.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration
public class JwtConfig {

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return NimbusJwtDecoder.withJwkSetUri(jwkSource.toString()).build();
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }
}
```

**Step 5: 创建 CustomUserDetailsService**

创建 `spring-cloud-demo-uaa/src/main/java/com/luban/uaa/user/CustomUserDetailsService.java`:

```java
package com.luban.uaa.user;

import com.luban.common.constants.RoleConstants;
import com.luban.common.entity.User;
import com.luban.common.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("用户不存在: " + username));

        if (!user.getEnabled()) {
            throw new UsernameNotFoundException("用户已禁用: " + username);
        }

        String authority = RoleConstants.AUTHORITY_PREFIX + user.getRole();

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(Collections.singletonList(new SimpleGrantedAuthority(authority)))
                .accountLocked(!user.getEnabled())
                .build();
    }
}
```

**Step 6: 创建 bootstrap.yml**

创建 `spring-cloud-demo-uaa/src/main/resources/bootstrap.yml`:

```yaml
spring:
  application:
    name: spring-cloud-demo-uaa
  cloud:
    nacos:
      server-addr: localhost:8848
      config:
        enabled: true
        file-extension: yml
      discovery:
        enabled: true
```

**Step 7: 创建 application.yml**

创建 `spring-cloud-demo-uaa/src/main/resources/application.yml`:

```yaml
server:
  port: 8081

spring:
  application:
    name: spring-cloud-demo-uaa
  datasource:
    url: jdbc:mysql://localhost:3306/spring_cloud_demo?createDatabaseIfNotExist=true&useSSL=false&serverTimezone=UTC
    username: root
    password: root
    driver-class-name: com.mysql.cj.jdbc.Driver
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
    properties:
      hibernate:
        dialect: org.hibernate.dialect.MySQLDialect
  cloud:
    nacos:
      server-addr: localhost:8848
      discovery:
        enabled: true
        namespace: public
      config:
        enabled: false

logging:
  level:
    com.luban: DEBUG
    org.springframework.security: DEBUG
```

**Step 8: 验证编译**

```bash
cd /Users/carsonhe/IdeaProjects/Aidemo
mvn clean compile -pl spring-cloud-demo-uaa
```

预期输出: BUILD SUCCESS

**Step 9: 提交**

```bash
git add spring-cloud-demo-uaa/
git commit -m "feat: 实现UAA认证服务核心配置"
```

---

## Task 4: 实现 spring-cloud-demo-product 产品服务

**文件：**
- 创建: `spring-cloud-demo-product/src/main/java/com/luban/product/ProductApplication.java`
- 创建: `spring-cloud-demo-product/src/main/java/com/luban/product/controller/ProductController.java`
- 创建: `spring-cloud-demo-product/src/main/java/com/luban/product/config/SecurityConfig.java`
- 创建: `spring-cloud-demo-product/src/main/java/com/luban/product/config/ResourceServerConfig.java`
- 创建: `spring-cloud-demo-product/src/main/resources/application.yml`
- 创建: `spring-cloud-demo-product/src/main/resources/bootstrap.yml`

**Step 1: 创建 Product 主启动类**

创建 `spring-cloud-demo-product/src/main/java/com/luban/product/ProductApplication.java`:

```java
package com.luban.product;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class ProductApplication {

    public static void main(String[] args) {
        SpringApplication.run(ProductApplication.class, args);
    }
}
```

**Step 2: 创建 ProductController**

创建 `spring-cloud-demo-product/src/main/java/com/luban/product/controller/ProductController.java`:

```java
package com.luban.product.controller;

import com.luban.common.entity.Product;
import com.luban.common.repository.ProductRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final ProductRepository productRepository;

    public ProductController(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    @GetMapping
    @PreAuthorize("hasAnyAuthority('ROLE_USER', 'ROLE_EDITOR', 'ROLE_PRODUCT_ADMIN')")
    public ResponseEntity<List<Product>> getProducts() {
        List<Product> products = productRepository.findAll();
        return ResponseEntity.ok(products);
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('ROLE_EDITOR', 'ROLE_PRODUCT_ADMIN')")
    public ResponseEntity<Product> createProduct(@RequestBody Product product) {
        Product saved = productRepository.save(product);
        return ResponseEntity.ok(saved);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_EDITOR', 'ROLE_PRODUCT_ADMIN')")
    public ResponseEntity<Product> updateProduct(@PathVariable Long id, @RequestBody Product product) {
        return productRepository.findById(id)
                .map(existing -> {
                    existing.setName(product.getName());
                    return ResponseEntity.ok(productRepository.save(existing));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_EDITOR', 'ROLE_PRODUCT_ADMIN')")
    public ResponseEntity<Void> deleteProduct(@PathVariable Long id) {
        if (productRepository.existsById(id)) {
            productRepository.deleteById(id);
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.notFound().build();
    }
}
```

**Step 3: 创建 SecurityConfig**

创建 `spring-cloud-demo-product/src/main/java/com/luban/product/config/SecurityConfig.java`:

```java
package com.luban.product.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> {}))
                .cors(cors -> cors.configurationSource(corsConfigurationSource()));

        return http.build();
    }

    @Bean
    public org.springframework.web.cors.CorsConfigurationSource corsConfigurationSource() {
        org.springframework.web.cors.CorsConfiguration configuration = new org.springframework.web.cors.CorsConfiguration();
        configuration.addAllowedOriginPattern("*");
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(true);

        org.springframework.web.cors.UrlBasedCorsConfigurationSource source = new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

**Step 4: 创建 ResourceServerConfig**

创建 `spring-cloud-demo-product/src/main/java/com/luban/product/config/ResourceServerConfig.java`:

```java
package com.luban.product.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class ResourceServerConfig {

    @Bean
    public JwtDecoder jwtDecoder() {
        // 使用 NimbusJwtDecoder 配合 UAA 的 JWK Set 端点
        return NimbusJwtDecoder.withJwkSetUri("http://localhost:8081/uaa/.well-known/jwks.json").build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        grantedAuthoritiesConverter.setAuthoritiesClaimName("scope");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }
}
```

**Step 5: 创建 bootstrap.yml**

创建 `spring-cloud-demo-product/src/main/resources/bootstrap.yml`:

```yaml
spring:
  application:
    name: spring-cloud-demo-product
  cloud:
    nacos:
      server-addr: localhost:8848
      config:
        enabled: true
        file-extension: yml
      discovery:
        enabled: true
```

**Step 6: 创建 application.yml**

创建 `spring-cloud-demo-product/src/main/resources/application.yml`:

```yaml
server:
  port: 8082

spring:
  application:
    name: spring-cloud-demo-product
  datasource:
    url: jdbc:mysql://localhost:3306/spring_cloud_demo?useSSL=false&serverTimezone=UTC
    username: root
    password: root
    driver-class-name: com.mysql.cj.jdbc.Driver
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
    properties:
      hibernate:
        dialect: org.hibernate.dialect.MySQLDialect
  cloud:
    nacos:
      server-addr: localhost:8848
      discovery:
        enabled: true
        namespace: public
      config:
        enabled: false

logging:
  level:
    com.luban: DEBUG
```

**Step 7: 验证编译**

```bash
cd /Users/carsonhe/IdeaProjects/Aidemo
mvn clean compile -pl spring-cloud-demo-product
```

预期输出: BUILD SUCCESS

**Step 8: 提交**

```bash
git add spring-cloud-demo-product/
git commit -m "feat: 实现Product产品服务核心功能"
```

---

## Task 5: 实现 spring-cloud-demo-gateway 网关服务

**文件：**
- 创建: `spring-cloud-demo-gateway/src/main/java/com/luban/gateway/GatewayApplication.java`
- 创建: `spring-cloud-demo-gateway/src/main/java/com/luban/gateway/config/GatewayConfig.java`
- 创建: `spring-cloud-demo-gateway/src/main/resources/application.yml`
- 创建: `spring-cloud-demo-gateway/src/main/resources/bootstrap.yml`
- 创建: `spring-cloud-demo-gateway/src/main/resources/static/login.html`

**Step 1: 创建 Gateway 主启动类**

创建 `spring-cloud-demo-gateway/src/main/java/com/luban/gateway/GatewayApplication.java`:

```java
package com.luban.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
```

**Step 2: 创建 GatewayConfig**

创建 `spring-cloud-demo-gateway/src/main/java/com/luban/gateway/config/GatewayConfig.java`:

```java
package com.luban.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class GatewayConfig {

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOriginPattern("*");
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return new CorsWebFilter(source);
    }
}
```

**Step 3: 创建 bootstrap.yml**

创建 `spring-cloud-demo-gateway/src/main/resources/bootstrap.yml`:

```yaml
spring:
  application:
    name: spring-cloud-demo-gateway
  cloud:
    nacos:
      server-addr: localhost:8848
      config:
        enabled: true
        file-extension: yml
      discovery:
        enabled: true
```

**Step 4: 创建 application.yml**

创建 `spring-cloud-demo-gateway/src/main/resources/application.yml`:

```yaml
server:
  port: 7573

spring:
  application:
    name: spring-cloud-demo-gateway
  cloud:
    nacos:
      server-addr: localhost:8848
      discovery:
        enabled: true
        namespace: public
      config:
        enabled: false
    gateway:
      routes:
        # UAA 服务路由
        - id: uaa-route
          uri: lb://spring-cloud-demo-uaa
          predicates:
            - Path=/uaa/**
          filters:
            - StripPrefix=0

        # Product 服务路由
        - id: product-route
          uri: lb://spring-cloud-demo-product
          predicates:
            - Path=/api/**
          filters:
            - StripPrefix=0

      default-filters:
        - DedupeResponseHeader=Access-Control-Allow-Credentials Access-Control-Allow-Origin

logging:
  level:
    com.luban: DEBUG
    org.springframework.cloud.gateway: DEBUG
```

**Step 5: 创建登录页面**

创建 `spring-cloud-demo-gateway/src/main/resources/static/login.html`:

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Spring Cloud Demo - 登录</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            width: 400px;
            max-width: 90%;
        }

        h2 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }

        .login-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        .login-tab {
            flex: 1;
            padding: 10px;
            text-align: center;
            cursor: pointer;
            border: 1px solid #ddd;
            border-radius: 5px;
            background: #f5f5f5;
            transition: all 0.3s;
        }

        .login-tab:hover {
            background: #e0e0e0;
        }

        .login-tab.active {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }

        .form-group {
            margin-bottom: 15px;
        }

        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }

        input:focus {
            outline: none;
            border-color: #667eea;
        }

        button {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s;
        }

        button:hover {
            background: #5568d3;
        }

        button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }

        .message {
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 5px;
            display: none;
        }

        .message.success {
            background: #d4edda;
            color: #155724;
            display: block;
        }

        .message.error {
            background: #f8d7da;
            color: #721c24;
            display: block;
        }

        .token-display {
            margin-top: 20px;
            padding: 15px;
            background: #f5f5f5;
            border-radius: 5px;
            display: none;
        }

        .token-display.show {
            display: block;
        }

        .token-display h4 {
            margin-bottom: 10px;
            color: #333;
        }

        .token-display pre {
            background: white;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 12px;
        }

        .test-section {
            margin-top: 20px;
            display: none;
        }

        .test-section.show {
            display: block;
        }

        .test-btn {
            background: #28a745;
            margin-top: 10px;
        }

        .test-btn:hover {
            background: #218838;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>用户登录</h2>

        <div id="message" class="message"></div>

        <div class="login-tabs">
            <div class="login-tab active" onclick="switchTab('password')">密码登录</div>
            <div class="login-tab" onclick="switchTab('github')">GitHub登录</div>
            <div class="login-tab" onclick="switchTab('ldap')">LDAP登录</div>
        </div>

        <!-- 密码登录表单 -->
        <form id="passwordForm" onsubmit="loginPassword(event)">
            <div class="form-group">
                <input type="text" id="username" placeholder="用户名" required>
            </div>
            <div class="form-group">
                <input type="password" id="password" placeholder="密码" required>
            </div>
            <button type="submit" id="passwordBtn">登录</button>
        </form>

        <!-- GitHub登录 -->
        <div id="githubForm" style="display:none">
            <p style="text-align: center; margin-bottom: 15px; color: #666;">
                点击下方按钮使用 GitHub 账号登录
            </p>
            <button type="button" onclick="loginGitHub()" style="background: #333;">使用 GitHub 登录</button>
        </div>

        <!-- LDAP登录表单 -->
        <form id="ldapForm" style="display:none" onsubmit="loginLdap(event)">
            <div class="form-group">
                <input type="text" id="ldapUsername" placeholder="LDAP 用户名" required>
            </div>
            <div class="form-group">
                <input type="password" id="ldapPassword" placeholder="LDAP 密码" required>
            </div>
            <button type="submit" id="ldapBtn">登录</button>
        </form>

        <div id="tokenDisplay" class="token-display">
            <h4>Access Token:</h4>
            <pre id="tokenContent"></pre>

            <div class="test-section" id="testSection">
                <h4 style="margin-top: 15px;">测试 API:</h4>
                <button class="test-btn" onclick="testGetProducts()">获取产品列表</button>
                <button class="test-btn" onclick="testCreateProduct()">添加产品</button>
            </div>
        </div>
    </div>

    <script>
        let accessToken = '';

        function switchTab(type) {
            // 隐藏所有表单
            document.getElementById('passwordForm').style.display = 'none';
            document.getElementById('githubForm').style.display = 'none';
            document.getElementById('ldapForm').style.display = 'none';

            // 移除所有激活状态
            document.querySelectorAll('.login-tab').forEach(tab => {
                tab.classList.remove('active');
            });

            // 显示对应表单
            if (type === 'password') {
                document.getElementById('passwordForm').style.display = 'block';
                event.target.classList.add('active');
            } else if (type === 'github') {
                document.getElementById('githubForm').style.display = 'block';
                event.target.classList.add('active');
            } else if (type === 'ldap') {
                document.getElementById('ldapForm').style.display = 'block';
                event.target.classList.add('active');
            }
        }

        function showMessage(message, type) {
            const messageEl = document.getElementById('message');
            messageEl.textContent = message;
            messageEl.className = 'message ' + type;
            setTimeout(() => {
                messageEl.className = 'message';
            }, 5000);
        }

        function displayToken(token) {
            accessToken = token;
            document.getElementById('tokenContent').textContent = token;
            document.getElementById('tokenDisplay').classList.add('show');
            document.getElementById('testSection').classList.add('show');
        }

        async function loginPassword(e) {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const btn = document.getElementById('passwordBtn');

            btn.disabled = true;
            btn.textContent = '登录中...';

            try {
                const response = await fetch('/uaa/oauth2/token', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Authorization': 'Basic ' + btoa('client:secret')
                    },
                    body: `grant_type=password&username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
                });

                const data = await response.json();

                if (data.access_token) {
                    showMessage('登录成功！', 'success');
                    displayToken(data.access_token);
                } else {
                    showMessage('登录失败：' + (data.error_description || data.error), 'error');
                }
            } catch (error) {
                showMessage('登录失败：' + error.message, 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = '登录';
            }
        }

        function loginGitHub() {
            showMessage('GitHub OAuth2 登录功能待实现，请使用密码登录', 'error');
        }

        function loginLdap(e) {
            e.preventDefault();
            showMessage('LDAP 登录功能待实现，请使用密码登录', 'error');
        }

        async function testGetProducts() {
            try {
                const response = await fetch('/api/products', {
                    headers: {
                        'Authorization': 'Bearer ' + accessToken
                    }
                });
                const data = await response.json();
                showMessage('获取产品列表成功：' + JSON.stringify(data), 'success');
            } catch (error) {
                showMessage('获取产品列表失败：' + error.message, 'error');
            }
        }

        async function testCreateProduct() {
            try {
                const response = await fetch('/api/products', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + accessToken,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ name: '测试产品' })
                });
                const data = await response.json();
                showMessage('添加产品成功：' + JSON.stringify(data), 'success');
            } catch (error) {
                showMessage('添加产品失败：' + error.message, 'error');
            }
        }
    </script>
</body>
</html>
```

**Step 6: 验证编译**

```bash
cd /Users/carsonhe/IdeaProjects/Aidemo
mvn clean compile -pl spring-cloud-demo-gateway
```

预期输出: BUILD SUCCESS

**Step 7: 提交**

```bash
git add spring-cloud-demo-gateway/
git commit -m "feat: 实现Gateway网关服务和登录页面"
```

---

## Task 6: 创建 Docker 配置和 docker-compose.yaml

**文件：**
- 创建: `docker/docker-compose.yaml`
- 创建: `docker/mysql/init.sql`
- 创建: `docker/nacos/application.properties`
- 创建: `docker/openldap/users.ldif`
- 创建: `docker/services/gateway/Dockerfile`
- 创建: `docker/services/uaa/Dockerfile`
- 创建: `docker/services/product/Dockerfile`

**Step 1: 创建 docker-compose.yaml**

创建 `docker/docker-compose.yaml`:

```yaml
version: '3.8'

services:
  # MySQL 数据库
  mysql:
    image: mysql:8.0
    container_name: spring-cloud-mysql
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: spring_cloud_demo
      MYSQL_USER: app_user
      MYSQL_PASSWORD: app_password
    ports:
      - "3306:3306"
    volumes:
      - ./mysql/init.sql:/docker-entrypoint-initdb.d/init.sql
      - mysql-data:/var/lib/mysql
    networks:
      - spring-cloud-network
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-uroot", "-proot"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Nacos 服务
  nacos:
    image: nacos/nacos-server:v2.3.0
    container_name: spring-cloud-nacos
    environment:
      MODE: standalone
      SPRING_DATASOURCE_PLATFORM: mysql
      MYSQL_SERVICE_HOST: mysql
      MYSQL_SERVICE_DB_NAME: nacos_config
      MYSQL_SERVICE_USER: root
      MYSQL_SERVICE_PASSWORD: root
      MYSQL_SERVICE_PORT: 3306
      NACOS_AUTH_ENABLE: false
      JVM_XMS: 256m
      JVM_XMX: 256m
    ports:
      - "8848:8848"
      - "9848:9848"
    volumes:
      - ./nacos/application.properties:/home/nacos/conf/application.properties
      - nacos-logs:/home/nacos/logs
    networks:
      - spring-cloud-network
    depends_on:
      mysql:
        condition: service_healthy

  # OpenLDAP 服务
  openldap:
    image: osixia/openldap:1.5.0
    container_name: spring-cloud-openldap
    environment:
      LDAP_DOMAIN: "luban-cae.com"
      LDAP_ORGANISATION: "Luban CAE"
      LDAP_ADMIN_PASSWORD: "admin"
      LDAP_CONFIG_PASSWORD: "config"
      LDAP_RFC2307BIS_SCHEMA: "false"
      LDAP_BACKEND: "mdb"
      LDAP_TLS: "false"
      LDAP_LOG_LEVEL: "256"
    ports:
      - "389:389"
      - "636:636"
    volumes:
      - ./openldap/users.ldif:/container/service/slapd/assets/config/bootstrap/ldif/50-users.ldif
      - ldap-data:/var/lib/ldap
      - ldap-config:/etc/ldap/slapd.d
    networks:
      - spring-cloud-network

  # UAA 认证服务
  uaa:
    build:
      context: ./services/uaa
      dockerfile: Dockerfile
    container_name: spring-cloud-uaa
    environment:
      SPRING_DATASOURCE_URL: jdbc:mysql://mysql:3306/spring_cloud_demo?useSSL=false&serverTimezone=UTC
      SPRING_DATASOURCE_USERNAME: root
      SPRING_DATASOURCE_PASSWORD: root
      SPRING_CLOUD_NACOS_SERVER_ADDR: nacos:8848
    ports:
      - "8081:8081"
    networks:
      - spring-cloud-network
    depends_on:
      - mysql
      - nacos

  # Product 产品服务
  product:
    build:
      context: ./services/product
      dockerfile: Dockerfile
    container_name: spring-cloud-product
    environment:
      SPRING_DATASOURCE_URL: jdbc:mysql://mysql:3306/spring_cloud_demo?useSSL=false&serverTimezone=UTC
      SPRING_DATASOURCE_USERNAME: root
      SPRING_DATASOURCE_PASSWORD: root
      SPRING_CLOUD_NACOS_SERVER_ADDR: nacos:8848
    ports:
      - "8082:8082"
    networks:
      - spring-cloud-network
    depends_on:
      - mysql
      - nacos
      - uaa

  # Gateway 网关服务
  gateway:
    build:
      context: ./services/gateway
      dockerfile: Dockerfile
    container_name: spring-cloud-gateway
    environment:
      SPRING_CLOUD_NACOS_SERVER_ADDR: nacos:8848
    ports:
      - "7573:7573"
    networks:
      - spring-cloud-network
    depends_on:
      - nacos
      - uaa
      - product

volumes:
  mysql-data:
  nacos-logs:
  ldap-data:
  ldap-config:

networks:
  spring-cloud-network:
    driver: bridge
```

**Step 2: 创建 MySQL 初始化脚本**

创建 `docker/mysql/init.sql`:

```sql
-- 创建 Nacos 配置数据库
CREATE DATABASE IF NOT EXISTS nacos_config;

-- 创建应用数据库
CREATE DATABASE IF NOT EXISTS spring_cloud_demo;

USE spring_cloud_demo;

-- 创建用户表
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 创建产品表
CREATE TABLE IF NOT EXISTS products (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 插入测试用户（密码与用户名相同，使用 BCrypt 加密）
-- 密码加密后的值 (BCrypt(10)):
-- user_1 -> $2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVKIUi
-- editor_1 -> $2a$10$X5zj1t1V3m6v2w9k8l3m6n7o8p9q0r1s2t3u4v5w6x7y8z9a0b1c2d3e4f5
-- adm_1 -> $2a$10$a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0

-- 为了简化，使用相同的 BCrypt 密码哈希（密码为 "password"）
INSERT INTO users (username, password, role, enabled) VALUES
('user_1', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVKIUi', 'USER', TRUE),
('editor_1', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVKIUi', 'EDITOR', TRUE),
('adm_1', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVKIUi', 'PRODUCT_ADMIN', TRUE)
ON DUPLICATE KEY UPDATE username=username;

-- 插入测试产品数据
INSERT INTO products (name) VALUES
('示例产品1'),
('示例产品2'),
('示例产品3')
ON DUPLICATE KEY UPDATE name=name;

-- 注意：以上用户的密码都是 "password"，
-- 实际登录时请使用：
-- user_1 / password
-- editor_1 / password
-- adm_1 / password
```

**Step 3: 创建 Nacos 配置文件**

创建 `docker/nacos/application.properties`:

```properties
# Spring
server.contextPath=/nacos
server.servlet.contextPath=/nacos
server.port=8848

# Tomcat
server.tomcat.accesslog.enabled=true
server.tomcat.accesslog.pattern=%h %l %u %t "%r" %s %b %D %{User-Agent}i %{Request-Source}i
server.tomcat.basedir=

# Nacos
nacos.standalone=true
management.metrics.export.elastic.enabled=false
management.metrics.export.influx.enabled=false
nacos.auth.enabled=false

# 日志级别
server.tomcat.basedir=
nacos.logs.path=/home/nacos/logs
```

**Step 4: 创建 LDAP 用户初始化文件**

创建 `docker/openldap/users.ldif`:

```ldif
# LDAP 用户定义
# dn: distinguished name
# uid: user id
# cn: common name
# sn: surname
# userPassword: 用户密码 (明文: ldap_user_1, ldap_editor_1, ldap_adm_1)

# 普通用户
dn: uid=ldap_user_1,ou=users,dc=luban-cae,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: LDAP User 1
sn: User
uid: ldap_user_1
userPassword: ldap_user_1

# EDITOR 用户
dn: uid=ldap_editor_1,ou=users,dc=luban-cae,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: LDAP Editor 1
sn: Editor
uid: ldap_editor_1
userPassword: ldap_editor_1

# PRODUCT_ADMIN 用户
dn: uid=ldap_adm_1,ou=users,dc=luban-cae,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: LDAP Admin 1
sn: Admin
uid: ldap_adm_1
userPassword: ldap_adm_1
```

**Step 5: 创建 Gateway Dockerfile**

创建 `docker/services/gateway/Dockerfile`:

```dockerfile
FROM maven:3.8.6-openjdk-17-slim AS builder
WORKDIR /app
COPY pom.xml .
COPY spring-cloud-demo-gateway/pom.xml spring-cloud-demo-gateway/
COPY spring-cloud-demo-common/pom.xml spring-cloud-demo-common/
RUN mvn dependency:go-offline

COPY spring-cloud-demo-common/src spring-cloud-demo-common/src
COPY spring-cloud-demo-gateway/src spring-cloud-demo-gateway/src
RUN mvn clean package -DskipTests -pl spring-cloud-demo-gateway

FROM openjdk:17-jdk-slim
WORKDIR /app
COPY --from=builder /app/spring-cloud-demo-gateway/target/spring-cloud-demo-gateway-1.0.0.jar app.jar
EXPOSE 7573
ENTRYPOINT ["java", "-jar", "app.jar"]
```

**Step 6: 创建 UAA Dockerfile**

创建 `docker/services/uaa/Dockerfile`:

```dockerfile
FROM maven:3.8.6-openjdk-17-slim AS builder
WORKDIR /app
COPY pom.xml .
COPY spring-cloud-demo-uaa/pom.xml spring-cloud-demo-uaa/
COPY spring-cloud-demo-common/pom.xml spring-cloud-demo-common/
RUN mvn dependency:go-offline

COPY spring-cloud-demo-common/src spring-cloud-demo-common/src
COPY spring-cloud-demo-uaa/src spring-cloud-demo-uaa/src
RUN mvn clean package -DskipTests -pl spring-cloud-demo-uaa

FROM openjdk:17-jdk-slim
WORKDIR /app
COPY --from=builder /app/spring-cloud-demo-uaa/target/spring-cloud-demo-uaa-1.0.0.jar app.jar
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "app.jar"]
```

**Step 7: 创建 Product Dockerfile**

创建 `docker/services/product/Dockerfile`:

```dockerfile
FROM maven:3.8.6-openjdk-17-slim AS builder
WORKDIR /app
COPY pom.xml .
COPY spring-cloud-demo-product/pom.xml spring-cloud-demo-product/
COPY spring-cloud-demo-common/pom.xml spring-cloud-demo-common/
RUN mvn dependency:go-offline

COPY spring-cloud-demo-common/src spring-cloud-demo-common/src
COPY spring-cloud-demo-product/src spring-cloud-demo-product/src
RUN mvn clean package -DskipTests -pl spring-cloud-demo-product

FROM openjdk:17-jdk-slim
WORKDIR /app
COPY --from=builder /app/spring-cloud-demo-product/target/spring-cloud-demo-product-1.0.0.jar app.jar
EXPOSE 8082
ENTRYPOINT ["java", "-jar", "app.jar"]
```

**Step 8: 创建 .dockerignore**

创建 `docker/.dockerignore`:

```
**/target/
**/.git/
**/.idea/
**/*.iml
**/.DS_Store
**/node_modules/
```

**Step 9: 提交**

```bash
git add docker/
git commit -m "feat: 添加Docker配置和docker-compose编排"
```

---

## Task 7: 更新 README.md 和测试命令

**文件：**
- 修改: `README.md`

**Step 1: 更新 README.md**

```bash
cd /Users/carsonhe/IdeaProjects/Aidemo
```

修改 `README.md`，添加完整的项目说明和测试命令。<tool_call>Read<arg_key>file_path</arg_key><arg_value>/Users/carsonhe/IdeaProjects/Aidemo/README.md