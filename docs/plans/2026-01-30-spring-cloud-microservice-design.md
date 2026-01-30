# Spring Cloud 微服务项目设计文档

**项目名称：** spring-cloud-demo
**设计日期：** 2026-01-30
**技术栈：** Spring Boot 3.2.x + Spring Cloud 2023.0.x

---

## 1. 整体架构

项目采用典型的 Spring Cloud 微服务架构，所有服务通过 Nacos 进行服务注册与配置管理。外部请求只能通过 Gateway（端口 7573）访问，Gateway 根据路由规则转发到后端服务。

### 1.1 模块结构

```
spring-cloud-demo/
├── spring-cloud-demo-common/    # 公共模块（实体、工具类、常量）
├── spring-cloud-demo-uaa/       # 认证授权服务
├── spring-cloud-demo-gateway/   # API 网关
├── spring-cloud-demo-product/   # 产品服务
└── docker/                      # Docker 配置文件
    ├── docker-compose.yaml
    ├── nacos/
    ├── mysql/
    ├── openldap/
    └── services/
```

### 1.2 技术选型

| 组件 | 技术方案 |
|------|----------|
| 服务发现与配置中心 | Nacos 2.3.x |
| 认证服务器 | Spring Authorization Server 1.2.x |
| 数据持久化 | Spring Data JPA + MySQL 8.0 |
| LDAP 服务 | OpenLDAP (osixia/openldap:1.5.0) |
| API 网关 | Spring Cloud Gateway |

### 1.3 端口规划

| 服务 | 端口 | 说明 |
|------|------|------|
| Gateway | 7573 | 唯一对外开放端口 |
| UAA | 8081 | 内部服务 |
| Product | 8082 | 内部服务 |
| Nacos | 8848 | 内部服务 |

---

## 2. 认证服务设计 (UAA)

UAA 服务基于 Spring Authorization Server 实现，负责处理所有认证请求。

### 2.1 核心功能

1. **用户名密码登录**：使用 JPA 从 MySQL 验证用户信息
2. **JWT Token 签发**：签发包含用户角色的访问令牌
3. **GitHub OAuth2**：预留接口，配置模板已准备
4. **LDAP 登录**：预留接口，连接 OpenLDAP 的模板代码已准备

### 2.2 数据库设计

**users 表：**

| 字段 | 类型 | 说明 |
|------|------|------|
| id | BIGINT | 主键，自增 |
| username | VARCHAR(50) | 用户名，唯一 |
| password | VARCHAR(255) | BCrypt 加密密码 |
| role | VARCHAR(50) | 角色（USER/EDITOR/PRODUCT_ADMIN） |
| enabled | BOOLEAN | 是否启用 |

### 2.3 角色权限设计

```
PRODUCT_ADMIN → 包含 EDITOR + USER 所有权限
EDITOR → 包含 USER 所有权限
USER → 基础查看权限
```

### 2.4 认证流程

1. 用户通过登录页面提交凭证
2. Gateway 转发到 UAA 的 `/oauth2/token` 端点
3. UAA 验证凭证，签发 JWT Token
4. 客户端获得 Token 后，在请求头中携带 `Authorization: Bearer <token>`

---

## 3. Product 服务设计

Product 服务负责产品 CRUD 操作，使用 Spring Data JPA 访问 MySQL。

### 3.1 数据库设计

**products 表：**

| 字段 | 类型 | 说明 |
|------|------|------|
| id | BIGINT | 主键，自增 |
| name | VARCHAR(100) | 产品名称 |

### 3.2 API 端点与权限

| 端点 | 方法 | 所需角色 | 说明 |
|------|------|----------|------|
| `/api/products` | GET | USER | 查看产品列表 |
| `/api/products` | POST | EDITOR | 添加产品 |
| `/api/products/{id}` | PUT | EDITOR | 修改产品 |
| `/api/products/{id}` | DELETE | EDITOR | 删除产品 |

### 3.3 权限验证

```java
// 角色继承逻辑，使用 hasAnyAuthority 实现权限检查

@PreAuthorize("hasAnyAuthority('USER', 'EDITOR', 'PRODUCT_ADMIN')")
@GetMapping("/products")
List<Product> getProducts();

@PreAuthorize("hasAnyAuthority('EDITOR', 'PRODUCT_ADMIN')")
@PostMapping("/products")
Product createProduct(@RequestBody Product product);

@PreAuthorize("hasAnyAuthority('EDITOR', 'PRODUCT_ADMIN')")
@PutMapping("/products/{id}")
Product updateProduct(@PathVariable Long id, @RequestBody Product product);

@PreAuthorize("hasAnyAuthority('EDITOR', 'PRODUCT_ADMIN')")
@DeleteMapping("/products/{id}")
void deleteProduct(@PathVariable Long id);
```

---

## 4. Gateway 网关设计

Gateway 基于 Spring Cloud Gateway 实现，作为系统的唯一入口（端口 7573）。

### 4.1 核心功能

1. **路由转发**：根据路径前缀将请求转发到对应服务
2. **跨域处理**：配置 CORS 允许前端访问
3. **错误处理**：统一处理下游服务错误响应
4. **静态资源**：提供登录页面

### 4.2 路由规则

| 路径 | 目标服务 | 说明 |
|------|----------|------|
| `/uaa/**` | UAA (8081) | 认证服务 |
| `/api/products/**` | Product (8082) | 产品服务 |
| `/login.html` | 静态资源 | 登录页面 |

### 4.3 关键配置

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: uaa-route
          uri: lb://spring-cloud-demo-uaa
          predicates:
            - Path=/uaa/**
        - id: product-route
          uri: lb://spring-cloud-demo-product
          predicates:
            - Path=/api/**
      globalcors:
        corsConfigurations:
          '[/**]':
            allowedOrigins: "*"
            allowedMethods: "*"
            allowedHeaders: "*"
```

---

## 5. Docker 部署设计

使用 `docker-compose.yaml` 统一编排所有服务，实现一键启动。

### 5.1 服务组成

1. **MySQL**：官方镜像，初始化数据库脚本
2. **Nacos**：官方镜像，单机模式运行
3. **OpenLDAP**：使用 `osixia/openldap` 镜像，预置测试用户
4. **Java 服务**：通过多阶段构建生成镜像

### 5.2 网络隔离

只有 Gateway 暴露端口 7573，其他服务仅在内网通信，确保安全性。

---

## 6. 登录页面设计

登录页面使用纯 HTML + JavaScript 实现，支持三种登录方式的切换。

### 6.1 功能说明

- Tab 切换显示不同登录表单
- 密码登录直接调用 UAA 的 token 端点
- GitHub 登录重定向到 GitHub OAuth2 授权页面
- LDAP 登录调用预留的 LDAP 认证端点
- 成功后 Token 存储在 localStorage

### 6.2 登录方式

1. **密码登录**：用户名/密码验证
2. **GitHub 登录**：OAuth2 授权（预留接口）
3. **LDAP 登录**：LDAP 验证（预留接口）

---

## 7. 测试用户数据

### 7.1 MySQL 用户（密码登录）

| 用户名 | 密码 | 角色 |
|--------|------|------|
| user_1 | user_1 | USER |
| editor_1 | editor_1 | EDITOR |
| adm_1 | adm_1 | PRODUCT_ADMIN |

### 7.2 LDAP 用户

| 用户名 | 密码 | 角色 |
|--------|------|------|
| ldap_user_1 | ldap_user_1 | USER |
| ldap_editor_1 | ldap_editor_1 | EDITOR |
| ldap_adm_1 | ldap_adm_1 | PRODUCT_ADMIN |

### 7.3 GitHub OAuth2

登录后统一授予 EDITOR 角色。

---

## 8. 测试命令示例

### 8.1 获取 Access Token

```bash
curl -X POST http://localhost:7573/uaa/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=user_1&password=user_1&client_id=client&client_secret=secret"
```

**预期输出：**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 300
}
```

### 8.2 查看产品列表（USER 权限）

```bash
TOKEN="eyJhbGciOiJSUzI1NiJ9..."
curl -X GET http://localhost:7573/api/products \
  -H "Authorization: Bearer $TOKEN"
```

### 8.3 添加产品（EDITOR 权限）

```bash
curl -X POST http://localhost:7573/api/products \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"测试产品"}'
```

### 8.4 修改产品

```bash
curl -X PUT http://localhost:7573/api/products/1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"修改后的产品"}'
```

### 8.5 删除产品

```bash
curl -X DELETE http://localhost:7573/api/products/1 \
  -H "Authorization: Bearer $TOKEN"
```

---

## 9. 交付清单

1. ✅ JDK 版本说明（JDK 17+）
2. ✅ mvn clean install 成功
3. ✅ docker-compose up 自动启动数据库并创建数据库
4. ✅ 相关服务正确启动
5. ✅ CURL 命令可得到预期输出

---

## 10. 实现策略（渐进式）

**第一阶段（核心功能）：**
1. 搭建多模块 Maven 项目骨架
2. 实现 UAA 服务（用户名密码登录）
3. 实现 Product 服务（完整 CRUD）
4. 实现 Gateway 路由和静态资源
5. Docker Compose 一键部署

**第二阶段（扩展功能）：**
1. 添加 GitHub OAuth2 登录支持
2. 添加 LDAP 登录支持
3. 完善错误处理和日志

---

**登录地址：** http://localhost:7573/login.html
